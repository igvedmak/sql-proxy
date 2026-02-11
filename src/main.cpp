#include "core/pipeline.hpp"
#include "core/pipeline_builder.hpp"
#include "core/utils.hpp"
#include "core/database_type.hpp"
#include "config/config_loader.hpp"
#include "config/config_watcher.hpp"
#include "server/http_server.hpp"
#include "parser/parse_cache.hpp"
#include "policy/policy_engine.hpp"
#include "policy/policy_loader.hpp"
#include "server/rate_limiter.hpp"
#include "db/backend_registry.hpp"
#include "db/idb_backend.hpp"
#include "db/iconnection_pool.hpp"
#include "db/generic_query_executor.hpp"
#include "executor/circuit_breaker.hpp"
#include "executor/circuit_breaker_registry.hpp"
#include "classifier/classifier_registry.hpp"
#include "audit/audit_emitter.hpp"
#include "core/query_rewriter.hpp"
#include "security/brute_force_protector.hpp"
#include "security/sql_injection_detector.hpp"
#include "security/anomaly_detector.hpp"
#include "security/lineage_tracker.hpp"
#include "security/column_encryptor.hpp"
#include "security/local_key_manager.hpp"
#include "security/vault_key_manager.hpp"
#include "security/env_key_manager.hpp"
#include "security/compliance_reporter.hpp"
#include "schema/schema_manager.hpp"
#include "tenant/tenant_manager.hpp"
#include "plugin/plugin_loader.hpp"
#include "server/wire_server.hpp"
#include "server/graphql_handler.hpp"
#include "server/binary_rpc_server.hpp"
#include "alerting/alert_evaluator.hpp"
#include "server/dashboard_handler.hpp"
#include "server/waitable_rate_limiter.hpp"
#include "server/shutdown_coordinator.hpp"
#include "server/response_compressor.hpp"
#include "audit/audit_sampler.hpp"
#include "cache/result_cache.hpp"
#include "core/slow_query_tracker.hpp"
#include "core/query_cost_estimator.hpp"
#include "schema/schema_drift_detector.hpp"
#include "audit/audit_encryptor.hpp"
#include "server/adaptive_rate_controller.hpp"
#include "auth/auth_chain.hpp"
#include "auth/oidc_auth_provider.hpp"
#include "security/sql_firewall.hpp"
#include "db/tenant_pool_registry.hpp"
#include "analyzer/index_recommender.hpp"
#include "tenant/data_residency.hpp"
#include "security/column_version_tracker.hpp"
#include "analyzer/synthetic_data_generator.hpp"
#include "core/cost_based_rewriter.hpp"
#include "analyzer/schema_cache.hpp"

// Force-link backends (auto-register via static init)
#ifdef ENABLE_POSTGRESQL
#include "db/postgresql/pg_backend.hpp"
#endif
#ifdef ENABLE_MYSQL
#include "db/mysql/mysql_backend.hpp"
#endif

#include <memory>
#include <csignal>
#include <cstdlib>
#include <format>

using namespace sqlproxy;

// Global instances for signal handling and config watcher
std::shared_ptr<HttpServer> g_server;
std::shared_ptr<ConfigWatcher> g_config_watcher;
std::shared_ptr<WireServer> g_wire_server;
std::shared_ptr<BinaryRpcServer> g_binary_rpc_server;
std::shared_ptr<AlertEvaluator> g_alert_evaluator;
std::shared_ptr<ShutdownCoordinator> g_shutdown;
std::shared_ptr<SchemaDriftDetector> g_schema_drift_detector;
std::shared_ptr<AdaptiveRateController> g_adaptive_rate_controller;

// =========================================================================
// Explicit Backend Registration (ensures linker includes backend objects)
// =========================================================================

static void register_backends() {
    #ifdef ENABLE_POSTGRESQL
    BackendRegistry::instance().register_backend(
        DatabaseType::POSTGRESQL,
        [] { return std::make_unique<PgBackend>(); });
    #endif

    #ifdef ENABLE_MYSQL
    BackendRegistry::instance().register_backend(
        DatabaseType::MYSQL,
        [] { return std::make_unique<MysqlBackend>(); });
    #endif
}

void signal_handler(int signal) {
    utils::log::info(std::format("Received signal {}, shutting down...", signal));

    // Initiate graceful shutdown: stop accepting new requests
    if (g_shutdown) {
        g_shutdown->initiate_shutdown();
    }

    // Stop background services
    if (g_adaptive_rate_controller) {
        g_adaptive_rate_controller->stop();
    }
    if (g_schema_drift_detector) {
        g_schema_drift_detector->stop();
    }
    if (g_alert_evaluator) {
        g_alert_evaluator->stop();
    }
    if (g_config_watcher) {
        g_config_watcher->stop();
    }
    if (g_wire_server) {
        g_wire_server->stop();
    }
    if (g_binary_rpc_server) {
        g_binary_rpc_server->stop();
    }

    // Wait for in-flight requests to drain
    if (g_shutdown) {
        bool drained = g_shutdown->wait_for_drain();
        if (drained) {
            utils::log::info("All in-flight requests drained");
        } else {
            utils::log::warn(std::format("Shutdown timeout: {} requests still in flight",
                g_shutdown->in_flight_count()));
        }
    }

    if (g_server) {
        g_server->stop();
    }
    exit(0);
}

int main(int argc, char* argv[]) {
    try {
        // Register all available backends
        register_backends();

        utils::log::info("SQL Proxy Service starting...");

        // Setup signal handlers
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);

        // Configuration
        std::string config_file = "config/proxy.toml";
        if (argc > 1) {
            config_file = argv[1];
        }

        utils::log::info(std::format("[1/9] Loading configuration from {}", config_file));

        // Try to load full config via ConfigLoader
        auto config_result = ConfigLoader::load_from_file(config_file);

        // Extract config values (or use defaults)
        std::vector<Policy> policies;
        std::unordered_map<std::string, UserInfo> users;
        std::string db_conn_string = "postgresql://proxy_user:secure_password@postgres:5432/testdb";
        std::string db_type_str = "postgresql";
        std::string audit_file = "logs/audit.jsonl";
        AuditConfig audit_config;

        HierarchicalRateLimiter::Config rate_config;
        CacheConfig cache_config;
        cache_config.max_entries = 10000;
        cache_config.num_shards = 16;

        PoolConfig pool_config;
        pool_config.connection_string = db_conn_string;
        pool_config.min_connections = 2;
        pool_config.max_connections = 10;
        pool_config.connection_timeout = std::chrono::milliseconds{5000};
        pool_config.health_check_query = "SELECT 1";

        size_t max_sql_length = 102400;
        size_t max_result_rows = 10000;

        if (config_result.success) {
            const auto& cfg = config_result.config;
            utils::log::info(std::format("Config loaded: {} policies, {} users",
                                          cfg.policies.size(), cfg.users.size()));

            // Policies
            policies = cfg.policies;

            // Users
            users = cfg.users;

            // Server
            max_sql_length = cfg.server.max_sql_length;

            // Database connection
            if (!cfg.databases.empty()) {
                const auto& db = cfg.databases[0];
                db_conn_string = db.connection_string;
                db_type_str = db.type_str;
                pool_config.connection_string = db.connection_string;
                pool_config.min_connections = db.min_connections;
                pool_config.max_connections = db.max_connections;
                pool_config.connection_timeout = db.connection_timeout;
                pool_config.health_check_query = db.health_check_query;
                pool_config.idle_timeout = std::chrono::milliseconds{db.idle_timeout_seconds * 1000};
                max_result_rows = db.max_result_rows;
            }

            // Rate limiting
            rate_config.global_tokens_per_second = cfg.rate_limiting.global_tokens_per_second;
            rate_config.global_burst_capacity = cfg.rate_limiting.global_burst_capacity;
            rate_config.default_user_tokens_per_second = cfg.rate_limiting.per_user_default_tokens_per_second;
            rate_config.default_user_burst_capacity = cfg.rate_limiting.per_user_default_burst_capacity;

            // Cache
            cache_config = cfg.cache;

            // Audit
            audit_config = cfg.audit;
            audit_file = audit_config.output_file;

        } else {
            utils::log::warn(std::format("{} - using hardcoded defaults", config_result.error_message));

            // Hardcoded policies for demo
            Policy allow_select;
            allow_select.name = "allow_all_select";
            allow_select.priority = 50;
            allow_select.action = Decision::ALLOW;
            allow_select.users = {"*"};
            allow_select.scope.operations = {StatementType::SELECT};
            policies.emplace_back(std::move(allow_select));

            Policy block_ddl;
            block_ddl.name = "block_all_ddl";
            block_ddl.priority = 100;
            block_ddl.action = Decision::BLOCK;
            block_ddl.users = {"*"};
            block_ddl.scope.operations = {
                StatementType::CREATE_TABLE,
                StatementType::ALTER_TABLE,
                StatementType::DROP_TABLE
            };
            policies.emplace_back(std::move(block_ddl));

            // Hardcoded users
            users["admin"] = UserInfo{"admin", {"admin"}};
            users["analyst"] = UserInfo{"analyst", {"analyst", "readonly"}};
            users["developer"] = UserInfo{"developer", {"developer"}};
            users["auditor"] = UserInfo{"auditor", {"auditor", "readonly"}};
        }

        // Resolve database type
        DatabaseType db_type = parse_database_type(db_type_str);
        utils::log::info(std::format("[2/9] Database backend: {}", database_type_to_string(db_type)));

        // Create backend via registry
        auto backend = BackendRegistry::instance().create(db_type);

        utils::log::info(std::format("[3/9] Parse cache: {} entries, {} shards",
                                      cache_config.max_entries, cache_config.num_shards));
        auto parse_cache = std::make_shared<ParseCache>(
            cache_config.max_entries, cache_config.num_shards);

        utils::log::info(std::format("[4/9] SQL parser: {} ready", database_type_to_string(db_type)));
        auto parser = backend->create_parser(parse_cache);

        utils::log::info("[5/9] Policy engine initializing...");
        auto policy_engine = std::make_shared<PolicyEngine>();
        policy_engine->load_policies(policies);
        utils::log::info(std::format("Policies: {} loaded", policy_engine->policy_count()));

        utils::log::info("[6/9] Rate limiter: 4 levels (Global -> User -> DB -> User+DB)");
        auto rate_limiter = std::make_shared<HierarchicalRateLimiter>(rate_config);

        // Apply per-user rate limit overrides from config
        if (config_result.success) {
            for (const auto& limit : config_result.config.rate_limiting.per_user) {
                rate_limiter->set_user_limit(
                    limit.user, limit.tokens_per_second, limit.burst_capacity);
            }
            for (const auto& limit : config_result.config.rate_limiting.per_database) {
                rate_limiter->set_database_limit(
                    limit.database, limit.tokens_per_second, limit.burst_capacity);
            }
            for (const auto& limit : config_result.config.rate_limiting.per_user_per_database) {
                rate_limiter->set_user_database_limit(
                    limit.user, limit.database, limit.tokens_per_second, limit.burst_capacity);
            }
        }

        // Wrap rate limiter with queue if enabled
        std::shared_ptr<IRateLimiter> active_rate_limiter = rate_limiter;
        if (config_result.success && config_result.config.rate_limiting.queue_enabled) {
            WaitableRateLimiter::Config queue_cfg;
            queue_cfg.queue_enabled = true;
            queue_cfg.queue_timeout = std::chrono::milliseconds(
                config_result.config.rate_limiting.queue_timeout_ms);
            queue_cfg.max_queue_depth = config_result.config.rate_limiting.max_queue_depth;
            active_rate_limiter = std::make_shared<WaitableRateLimiter>(rate_limiter, queue_cfg);
            utils::log::info(std::format("Request queuing: enabled (timeout={}ms, depth={})",
                config_result.config.rate_limiting.queue_timeout_ms,
                config_result.config.rate_limiting.max_queue_depth));
        }

        utils::log::info("[7/9] Connection pool & executor initializing...");
        std::string db_name = "testdb";
        if (config_result.success && !config_result.config.databases.empty()) {
            db_name = config_result.config.databases[0].name;
        }

        CircuitBreaker::Config cb_config;
        if (config_result.success) {
            const auto& cb = config_result.config.circuit_breaker;
            cb_config.failure_threshold = static_cast<uint32_t>(cb.failure_threshold);
            cb_config.success_threshold = static_cast<uint32_t>(cb.success_threshold);
            cb_config.timeout = std::chrono::milliseconds(cb.timeout_ms);
            cb_config.half_open_max_calls = static_cast<uint32_t>(cb.half_open_max_calls);
        }
        utils::log::info(std::format("Creating circuit breaker for database: {} "
            "(threshold={}, timeout={}ms, half_open={})",
            db_name, cb_config.failure_threshold,
            cb_config.timeout.count(), cb_config.half_open_max_calls));
        auto circuit_breaker = std::make_shared<CircuitBreaker>(db_name, cb_config);

        // Per-tenant circuit breaker registry (uses same default config)
        auto cb_registry = std::make_shared<CircuitBreakerRegistry>(cb_config);
        utils::log::info("Per-tenant circuit breaker registry created");

        utils::log::info("Creating connection pool...");
        std::shared_ptr<IConnectionPool> pool;
        try {
            pool = backend->create_pool(db_name, pool_config, circuit_breaker);
            utils::log::info("Connection pool created successfully");
        } catch (const std::exception& pool_err) {
            utils::log::error(std::format("Pool creation error: {}", pool_err.what()));
            throw;
        }

        utils::log::info("Creating query executor...");
        GenericQueryExecutor::Config exec_config;
        exec_config.max_result_rows = static_cast<uint32_t>(max_result_rows);
        if (config_result.success && !config_result.config.databases.empty()) {
            exec_config.query_timeout_ms = static_cast<uint32_t>(
                config_result.config.databases[0].query_timeout.count());
        }
        auto executor = std::make_shared<GenericQueryExecutor>(pool, circuit_breaker, exec_config);
        utils::log::info("Query executor created successfully");

        utils::log::info(std::format("Executor: {} with circuit breaker", database_type_to_string(db_type)));

        utils::log::info("[8/9] Classifier & audit initializing...");
        std::shared_ptr<ClassifierRegistry> classifier;
        if (config_result.config.classification_enabled) {
            classifier = std::make_shared<ClassifierRegistry>();
        }
        utils::log::info(std::format("Classification: {}",
            config_result.config.classification_enabled ? "enabled" : "disabled"));
        std::shared_ptr<AuditEmitter> audit_emitter;
        if (config_result.success) {
            audit_emitter = std::make_shared<AuditEmitter>(audit_config);
            utils::log::info(std::format("Audit: file={}, webhook={}, syslog={}",
                audit_config.output_file,
                audit_config.webhook_enabled ? "enabled" : "disabled",
                audit_config.syslog_enabled ? "enabled" : "disabled"));
        } else {
            audit_emitter = std::make_shared<AuditEmitter>(audit_file);
            utils::log::info(std::format("Audit: writing to {}", audit_file));
        }

        // Create query rewriter (RLS + enforce_limit)
        std::shared_ptr<QueryRewriter> query_rewriter;
        if (config_result.success &&
            (!config_result.config.rls_rules.empty() || !config_result.config.rewrite_rules.empty())) {
            query_rewriter = std::make_shared<QueryRewriter>();
            query_rewriter->load_rules(config_result.config.rls_rules,
                                        config_result.config.rewrite_rules);
            utils::log::info(std::format("Query rewriter: {} RLS rules, {} rewrite rules",
                config_result.config.rls_rules.size(),
                config_result.config.rewrite_rules.size()));
        }

        // =====================================================================
        // Security components (Tier 4)
        // =====================================================================

        // SQL Injection Detector
        std::shared_ptr<SqlInjectionDetector> injection_detector;
        if (config_result.config.security.injection_detection_enabled) {
            SqlInjectionDetector::Config sqli_config;
            sqli_config.enabled = true;
            injection_detector = std::make_shared<SqlInjectionDetector>(sqli_config);
        }
        utils::log::info(std::format("SQL injection detector: {}",
            injection_detector ? "enabled" : "disabled"));

        // Anomaly Detector
        std::shared_ptr<AnomalyDetector> anomaly_detector;
        if (config_result.config.security.anomaly_detection_enabled) {
            AnomalyDetector::Config anomaly_config;
            anomaly_config.enabled = true;
            anomaly_detector = std::make_shared<AnomalyDetector>(anomaly_config);
        }
        utils::log::info(std::format("Anomaly detector: {}",
            anomaly_detector ? "enabled" : "disabled"));

        // Data Lineage Tracker
        std::shared_ptr<LineageTracker> lineage_tracker;
        if (config_result.config.security.lineage_tracking_enabled) {
            LineageTracker::Config lineage_config;
            lineage_config.enabled = true;
            lineage_tracker = std::make_shared<LineageTracker>(lineage_config);
        }
        utils::log::info(std::format("Lineage tracker: {}",
            lineage_tracker ? "enabled" : "disabled"));

        // Column Encryptor (with pluggable key manager)
        std::shared_ptr<IKeyManager> key_manager;  // Shared with audit encryptor
        std::shared_ptr<ColumnEncryptor> column_encryptor;
        if (config_result.success && config_result.config.encryption.enabled) {
            const auto& enc_cfg = config_result.config.encryption;

            // Key manager factory
            if (enc_cfg.key_manager_provider == "vault") {
                VaultKeyManagerConfig vault_cfg;
                vault_cfg.vault_addr = enc_cfg.vault_addr;
                vault_cfg.vault_token = enc_cfg.vault_token;
                vault_cfg.key_name = enc_cfg.vault_key_name;
                vault_cfg.mount = enc_cfg.vault_mount;
                vault_cfg.cache_ttl_seconds = enc_cfg.vault_cache_ttl_seconds;
                key_manager = std::make_shared<VaultKeyManager>(std::move(vault_cfg));
                utils::log::info("Key manager: Vault Transit");
            } else if (enc_cfg.key_manager_provider == "env") {
                key_manager = std::make_shared<EnvKeyManager>(enc_cfg.env_key_var);
                utils::log::info(std::format("Key manager: env var '{}'", enc_cfg.env_key_var));
            } else {
                key_manager = std::make_shared<LocalKeyManager>(enc_cfg.key_file);
                utils::log::info("Key manager: local file");
            }

            ColumnEncryptor::Config enc_config;
            enc_config.enabled = true;
            for (const auto& c : enc_cfg.columns) {
                enc_config.columns.emplace_back(c.database, c.table, c.column);
            }
            column_encryptor = std::make_shared<ColumnEncryptor>(key_manager, enc_config);
            utils::log::info(std::format("Column encryptor: {} columns configured",
                enc_config.columns.size()));
        }

        // Compliance Reporter
        auto compliance_reporter = std::make_shared<ComplianceReporter>(
            lineage_tracker, anomaly_detector, audit_emitter);

        // =====================================================================
        // Tier 5 components
        // =====================================================================

        // Schema Manager
        std::shared_ptr<SchemaManager> schema_manager;
        if (config_result.success && config_result.config.schema_management.enabled) {
            SchemaManagementConfig sm_config;
            sm_config.enabled = true;
            sm_config.require_approval = config_result.config.schema_management.require_approval;
            sm_config.max_history_entries = config_result.config.schema_management.max_history_entries;
            schema_manager = std::make_shared<SchemaManager>(sm_config);
            utils::log::info(std::format("Schema manager: enabled (approval={})",
                sm_config.require_approval ? "required" : "optional"));
        }

        // Tenant Manager
        std::shared_ptr<TenantManager> tenant_manager;
        if (config_result.success && config_result.config.tenants.enabled) {
            TenantConfig tenant_config;
            tenant_config.enabled = true;
            tenant_config.default_tenant = config_result.config.tenants.default_tenant;
            tenant_config.header_name = config_result.config.tenants.header_name;
            tenant_manager = std::make_shared<TenantManager>(tenant_config);
            utils::log::info(std::format("Tenant manager: enabled (default={})",
                tenant_config.default_tenant));
        }

        // Plugin Registry
        auto plugin_registry = std::make_shared<PluginRegistry>();
        if (config_result.success && !config_result.config.plugins.empty()) {
            for (const auto& plugin_cfg : config_result.config.plugins) {
                PluginConfig pc;
                pc.path = plugin_cfg.path;
                pc.type = plugin_cfg.type;
                pc.config = plugin_cfg.config;
                [[maybe_unused]] bool loaded = plugin_registry->load_plugin(pc);
            }
            utils::log::info(std::format("Plugins: {} classifier, {} audit sink",
                plugin_registry->classifier_plugins().size(),
                plugin_registry->audit_sink_plugins().size()));
        }

        // Tier B: Audit Sampler
        std::shared_ptr<AuditSampler> audit_sampler;
        if (config_result.success && config_result.config.audit_sampling.enabled) {
            AuditSampler::Config as_cfg;
            as_cfg.enabled = true;
            as_cfg.default_sample_rate = config_result.config.audit_sampling.default_sample_rate;
            as_cfg.select_sample_rate = config_result.config.audit_sampling.select_sample_rate;
            as_cfg.always_log_blocked = config_result.config.audit_sampling.always_log_blocked;
            as_cfg.always_log_writes = config_result.config.audit_sampling.always_log_writes;
            as_cfg.always_log_errors = config_result.config.audit_sampling.always_log_errors;
            as_cfg.deterministic = config_result.config.audit_sampling.deterministic;
            audit_sampler = std::make_shared<AuditSampler>(as_cfg);
            utils::log::info(std::format("Audit sampling: enabled (select_rate={:.1f}%, deterministic={})",
                as_cfg.select_sample_rate * 100, as_cfg.deterministic ? "yes" : "no"));
        }

        // Tier B: Result Cache
        std::shared_ptr<ResultCache> result_cache;
        if (config_result.success && config_result.config.result_cache.enabled) {
            ResultCache::Config rc_cfg;
            rc_cfg.enabled = true;
            rc_cfg.max_entries = config_result.config.result_cache.max_entries;
            rc_cfg.num_shards = config_result.config.result_cache.num_shards;
            rc_cfg.ttl = std::chrono::seconds(config_result.config.result_cache.ttl_seconds);
            rc_cfg.max_result_size_bytes = config_result.config.result_cache.max_result_size_bytes;
            result_cache = std::make_shared<ResultCache>(rc_cfg);
            utils::log::info(std::format("Result cache: enabled ({} entries, {}s TTL, {} shards)",
                rc_cfg.max_entries, config_result.config.result_cache.ttl_seconds, rc_cfg.num_shards));
        }

        // Tier C: Slow Query Tracker
        std::shared_ptr<SlowQueryTracker> slow_query_tracker;
        if (config_result.success && config_result.config.slow_query.enabled) {
            SlowQueryTracker::Config sq_cfg;
            sq_cfg.enabled = true;
            sq_cfg.threshold_ms = config_result.config.slow_query.threshold_ms;
            sq_cfg.max_entries = config_result.config.slow_query.max_entries;
            slow_query_tracker = std::make_shared<SlowQueryTracker>(sq_cfg);
            utils::log::info(std::format("Slow query tracker: enabled (threshold={}ms, max_entries={})",
                sq_cfg.threshold_ms, sq_cfg.max_entries));
        }

        // Tier F: Query Cost Estimator
        std::shared_ptr<QueryCostEstimator> query_cost_estimator;
        if (config_result.success && config_result.config.query_cost.enabled) {
            QueryCostEstimator::Config qc_cfg;
            qc_cfg.enabled = true;
            qc_cfg.max_cost = config_result.config.query_cost.max_cost;
            qc_cfg.max_estimated_rows = config_result.config.query_cost.max_estimated_rows;
            qc_cfg.log_estimates = config_result.config.query_cost.log_estimates;
            query_cost_estimator = std::make_shared<QueryCostEstimator>(pool, qc_cfg);
            utils::log::info(std::format("Query cost estimator: enabled (max_cost={:.0f}, max_rows={})",
                qc_cfg.max_cost, qc_cfg.max_estimated_rows));
        }

        // Index Recommender
        std::shared_ptr<IndexRecommender> index_recommender;
        if (config_result.success) {  // Always create if config loaded
            IndexRecommender::Config ir_cfg;
            ir_cfg.enabled = config_result.config.slow_query.enabled; // Enable if slow query tracking is on
            ir_cfg.min_occurrences = 3;
            ir_cfg.max_recommendations = 50;
            index_recommender = std::make_shared<IndexRecommender>(ir_cfg);
            if (ir_cfg.enabled) {
                utils::log::info("Index recommender: enabled");
            }
        }

        // Tier F: Schema Drift Detector
        if (config_result.success && config_result.config.schema_drift.enabled) {
            SchemaDriftDetector::Config sd_cfg;
            sd_cfg.enabled = true;
            sd_cfg.check_interval_seconds = config_result.config.schema_drift.check_interval_seconds;
            sd_cfg.database = config_result.config.schema_drift.database;
            sd_cfg.schema_name = config_result.config.schema_drift.schema_name;
            g_schema_drift_detector = std::make_shared<SchemaDriftDetector>(pool, sd_cfg);
            g_schema_drift_detector->start();
            utils::log::info(std::format("Schema drift detector: enabled (interval={}s, schema={})",
                sd_cfg.check_interval_seconds, sd_cfg.schema_name));
        }

        // =====================================================================
        // Tier G: Audit encryption, adaptive rate limiting
        // =====================================================================

        // Audit encryption at rest
        if (config_result.success && config_result.config.audit_encryption.enabled) {
            // Reuse existing key_manager or create one for audit
            std::shared_ptr<IKeyManager> audit_key_mgr = key_manager;
            if (!audit_key_mgr) {
                const auto& enc_cfg = config_result.config.encryption;
                if (enc_cfg.key_manager_provider == "env") {
                    audit_key_mgr = std::make_shared<EnvKeyManager>(enc_cfg.env_key_var);
                } else {
                    audit_key_mgr = std::make_shared<LocalKeyManager>(enc_cfg.key_file);
                }
            }
            AuditEncryptor::Config ae_cfg;
            ae_cfg.enabled = true;
            ae_cfg.key_id = config_result.config.audit_encryption.key_id;
            auto audit_enc = std::make_shared<AuditEncryptor>(audit_key_mgr, ae_cfg);
            audit_emitter->set_encryptor(audit_enc);
            utils::log::info(std::format("Audit encryption: enabled (key_id={})", ae_cfg.key_id));
        }

        // Adaptive rate limiting
        if (config_result.success && config_result.config.adaptive_rate_limiting.enabled) {
            AdaptiveRateController::Config arc_cfg;
            arc_cfg.enabled = true;
            arc_cfg.adjustment_interval_seconds = config_result.config.adaptive_rate_limiting.adjustment_interval_seconds;
            arc_cfg.latency_target_ms = config_result.config.adaptive_rate_limiting.latency_target_ms;
            arc_cfg.throttle_threshold_ms = config_result.config.adaptive_rate_limiting.throttle_threshold_ms;
            g_adaptive_rate_controller = std::make_shared<AdaptiveRateController>(
                rate_limiter, arc_cfg,
                rate_config.global_tokens_per_second,
                rate_config.global_burst_capacity);
            utils::log::info(std::format("Adaptive rate limiting: enabled (target={}ms, throttle={}ms, interval={}s)",
                arc_cfg.latency_target_ms, arc_cfg.throttle_threshold_ms, arc_cfg.adjustment_interval_seconds));
        }

        // SQL Firewall
        std::shared_ptr<SqlFirewall> sql_firewall;
        if (config_result.success && config_result.config.security.firewall_enabled) {
            SqlFirewall::Config fw_cfg;
            fw_cfg.enabled = true;
            const auto& fw_mode = config_result.config.security.firewall_mode;
            if (fw_mode == "learning") {
                fw_cfg.initial_mode = FirewallMode::LEARNING;
            } else if (fw_mode == "enforcing") {
                fw_cfg.initial_mode = FirewallMode::ENFORCING;
            } else {
                fw_cfg.initial_mode = FirewallMode::DISABLED;
            }
            sql_firewall = std::make_shared<SqlFirewall>(fw_cfg);
            utils::log::info(std::format("SQL firewall: enabled (mode={})", fw_mode));
        }

        // Per-tenant connection pools
        std::shared_ptr<TenantPoolRegistry> tenant_pool_registry;
        if (config_result.success && config_result.config.tenants.enabled) {
            TenantPoolRegistry::Config tpr_cfg;
            tpr_cfg.default_max_connections = pool_config.max_connections;
            tpr_cfg.default_min_connections = pool_config.min_connections;
            tenant_pool_registry = std::make_shared<TenantPoolRegistry>(tpr_cfg);
            utils::log::info("Per-tenant connection pool registry: enabled");
        }

        // Data residency enforcement
        std::shared_ptr<DataResidencyEnforcer> data_residency_enforcer;
        if (config_result.success && config_result.config.data_residency.enabled) {
            DataResidencyEnforcer::Config dre_cfg;
            dre_cfg.enabled = true;
            data_residency_enforcer = std::make_shared<DataResidencyEnforcer>(dre_cfg);
            // Populate database regions from config
            for (const auto& db : config_result.config.databases) {
                if (!db.region.empty()) {
                    data_residency_enforcer->set_database_region(db.name, db.region);
                }
            }
            utils::log::info(std::format("Data residency: enabled ({} databases with regions)",
                data_residency_enforcer->database_count()));
        }

        // Column version tracking
        std::shared_ptr<ColumnVersionTracker> column_version_tracker;
        if (config_result.success && config_result.config.column_versioning.enabled) {
            ColumnVersionTracker::Config cvt_cfg;
            cvt_cfg.enabled = true;
            cvt_cfg.max_events = config_result.config.column_versioning.max_events;
            column_version_tracker = std::make_shared<ColumnVersionTracker>(cvt_cfg);
            utils::log::info(std::format("Column versioning: enabled (max_events={})",
                cvt_cfg.max_events));
        }

        // Synthetic data generator
        std::shared_ptr<SyntheticDataGenerator> synthetic_data_generator;
        std::shared_ptr<SchemaCache> schema_cache;
        if (config_result.success && config_result.config.synthetic_data.enabled) {
            SyntheticDataGenerator::Config sdg_cfg;
            sdg_cfg.enabled = true;
            sdg_cfg.max_rows = config_result.config.synthetic_data.max_rows;
            synthetic_data_generator = std::make_shared<SyntheticDataGenerator>(sdg_cfg);
            schema_cache = std::make_shared<SchemaCache>();
            utils::log::info(std::format("Synthetic data: enabled (max_rows={})",
                sdg_cfg.max_rows));
        }

        // Cost-based query rewriting
        std::shared_ptr<CostBasedRewriter> cost_based_rewriter;
        if (config_result.success && config_result.config.cost_based_rewriting.enabled) {
            CostBasedRewriter::Config cbr_cfg;
            cbr_cfg.enabled = true;
            cbr_cfg.cost_threshold = config_result.config.cost_based_rewriting.cost_threshold;
            cbr_cfg.max_columns_for_star = config_result.config.cost_based_rewriting.max_columns_for_star;
            cost_based_rewriter = std::make_shared<CostBasedRewriter>(cbr_cfg);
            if (schema_cache) {
                cost_based_rewriter->set_schema_cache(schema_cache);
            }
            utils::log::info(std::format("Cost-based rewriting: enabled (max_star_cols={})",
                cbr_cfg.max_columns_for_star));
        }

        // Create pipeline via builder (with Tier 5 + Tier B + Tier C + Tier F + Tier G components)
        auto pipeline = PipelineBuilder()
            .with_parser(parser)
            .with_policy_engine(policy_engine)
            .with_rate_limiter(active_rate_limiter)
            .with_executor(executor)
            .with_classifier(classifier)
            .with_audit_emitter(audit_emitter)
            .with_rewriter(query_rewriter)
            .with_injection_detector(injection_detector)
            .with_anomaly_detector(anomaly_detector)
            .with_lineage_tracker(lineage_tracker)
            .with_column_encryptor(column_encryptor)
            .with_schema_manager(schema_manager)
            .with_tenant_manager(tenant_manager)
            .with_audit_sampler(audit_sampler)
            .with_result_cache(result_cache)
            .with_slow_query_tracker(slow_query_tracker)
            .with_circuit_breaker(circuit_breaker)
            .with_circuit_breaker_registry(cb_registry)
            .with_connection_pool(pool)
            .with_parse_cache(parse_cache)
            .with_query_cost_estimator(query_cost_estimator)
            .with_adaptive_rate_controller(g_adaptive_rate_controller)
            .with_sql_firewall(sql_firewall)
            .with_tenant_pool_registry(tenant_pool_registry)
            .with_index_recommender(index_recommender)
            .with_data_residency_enforcer(data_residency_enforcer)
            .with_column_version_tracker(column_version_tracker)
            .with_cost_based_rewriter(cost_based_rewriter)
            .with_masking_enabled(config_result.config.masking_enabled)
            .build();

        // Tier F: Retry with backoff
        if (config_result.success && config_result.config.retry.enabled) {
            Pipeline::RetryConfig rc;
            rc.enabled = true;
            rc.max_retries = config_result.config.retry.max_retries;
            rc.initial_backoff_ms = config_result.config.retry.initial_backoff_ms;
            rc.max_backoff_ms = config_result.config.retry.max_backoff_ms;
            pipeline->set_retry_config(rc);
            utils::log::info(std::format("Retry: enabled (max_retries={}, initial_backoff={}ms)",
                rc.max_retries, rc.initial_backoff_ms));
        }

        // GraphQL Handler
        std::shared_ptr<GraphQLHandler> graphql_handler;
        if (config_result.success && config_result.config.graphql.enabled) {
            GraphQLConfig gql_config;
            gql_config.enabled = true;
            gql_config.endpoint = config_result.config.graphql.endpoint;
            gql_config.max_query_depth = config_result.config.graphql.max_query_depth;
            gql_config.mutations_enabled = config_result.config.graphql.mutations_enabled;
            graphql_handler = std::make_shared<GraphQLHandler>(pipeline, gql_config);
            utils::log::info(std::format("GraphQL: enabled at {}", gql_config.endpoint));
        }

        // =====================================================================
        // Tier 2: Alerting
        // =====================================================================
        if (config_result.success && config_result.config.alerting.enabled) {
            g_alert_evaluator = std::make_shared<AlertEvaluator>(
                config_result.config.alerting, audit_emitter, rate_limiter);
            g_alert_evaluator->start();
            utils::log::info(std::format("Alerting: {} rules, eval every {}s",
                config_result.config.alerting.rules.size(),
                config_result.config.alerting.evaluation_interval_seconds));
        }

        // =====================================================================
        // Tier 2: Admin Dashboard
        // =====================================================================
        std::shared_ptr<DashboardHandler> dashboard_handler;
        {
            std::vector<DashboardUser> dash_users;
            for (const auto& [name, info] : users) {
                dash_users.emplace_back(name, info.roles);
            }
            dashboard_handler = std::make_shared<DashboardHandler>(
                pipeline, g_alert_evaluator, std::move(dash_users),
                config_result.config.routes);
        }
        utils::log::info("Dashboard: enabled at /dashboard");

        // Determine server bind address and port
        std::string host = "0.0.0.0";
        uint16_t port = 8080;
        if (config_result.success) {
            host = config_result.config.server.host;
            port = config_result.config.server.port;
        }

        // Tier B: Response compressor config
        ResponseCompressor::Config compressor_config;
        if (config_result.success) {
            compressor_config.enabled = config_result.config.server.compression_enabled;
            compressor_config.min_size_bytes = config_result.config.server.compression_min_size_bytes;
        }

        // Build feature flags for route gating
        const auto& cfg = config_result.config;
        FeatureFlags features;
        features.dry_run             = cfg.dry_run_enabled;
        features.openapi             = cfg.openapi_enabled;
        features.swagger_ui          = cfg.openapi_enabled;
        features.metrics             = cfg.metrics.enabled;
        features.slow_query          = cfg.slow_query.enabled;
        features.schema_drift        = cfg.schema_drift.enabled;
        features.classification      = cfg.classification_enabled;
        features.injection_detection = cfg.security.injection_detection_enabled;
        features.lineage_tracking    = cfg.security.lineage_tracking_enabled;
        features.masking             = cfg.masking_enabled;
        features.dashboard           = cfg.dashboard_enabled;
        features.data_residency      = cfg.data_residency.enabled;
        features.column_versioning   = cfg.column_versioning.enabled;
        features.synthetic_data      = cfg.synthetic_data.enabled;
        features.cost_based_rewriting = cfg.cost_based_rewriting.enabled;

        // Create HTTP server (with Tier 2 + Tier 5 + Tier B components)
        g_server = std::make_shared<HttpServer>(pipeline, host, port, users,
            config_result.config.server.admin_token, max_sql_length,
            compliance_reporter, lineage_tracker, schema_manager, graphql_handler,
            dashboard_handler, config_result.config.server.tls, compressor_config,
            config_result.config.routes, features,
            config_result.config.server.thread_pool_size);

        // Tier B: Graceful shutdown coordinator
        ShutdownCoordinator::Config shutdown_cfg;
        if (config_result.success) {
            shutdown_cfg.shutdown_timeout = std::chrono::milliseconds(
                config_result.config.server.shutdown_timeout_ms);
        }
        g_shutdown = std::make_shared<ShutdownCoordinator>(shutdown_cfg);
        g_server->set_shutdown_coordinator(g_shutdown);

        // Tier F: Schema drift detector
        if (g_schema_drift_detector) {
            g_server->set_schema_drift_detector(g_schema_drift_detector);
        }

        // Plugin hot-reload support
        g_server->set_plugin_registry(plugin_registry);

        // SQL Firewall
        if (sql_firewall) {
            g_server->set_sql_firewall(sql_firewall);
        }

        // Tenant provisioning API
        if (tenant_manager) {
            g_server->set_tenant_manager(tenant_manager);
        }

        // New features: wire to HTTP server
        if (data_residency_enforcer) {
            g_server->set_data_residency_enforcer(data_residency_enforcer);
        }
        if (column_version_tracker) {
            g_server->set_column_version_tracker(column_version_tracker);
        }
        if (synthetic_data_generator) {
            g_server->set_synthetic_data_generator(synthetic_data_generator);
            if (schema_cache) {
                g_server->set_schema_cache(schema_cache);
            }
        }

        // Tier E: Brute force protection
        if (config_result.success && config_result.config.security.brute_force_enabled) {
            BruteForceProtector::Config bf_cfg;
            bf_cfg.enabled = true;
            bf_cfg.max_attempts = config_result.config.security.brute_force_max_attempts;
            bf_cfg.window_seconds = config_result.config.security.brute_force_window_seconds;
            bf_cfg.lockout_seconds = config_result.config.security.brute_force_lockout_seconds;
            bf_cfg.max_lockout_seconds = config_result.config.security.brute_force_max_lockout_seconds;
            g_server->set_brute_force_protector(
                std::make_shared<BruteForceProtector>(bf_cfg));
        }

        // OIDC/OAuth2 authentication provider
        if (config_result.success && config_result.config.auth.provider == "oidc") {
            OidcConfig oidc_cfg;
            oidc_cfg.issuer = config_result.config.auth.oidc_issuer;
            oidc_cfg.audience = config_result.config.auth.oidc_audience;
            oidc_cfg.jwks_uri = config_result.config.auth.oidc_jwks_uri;
            oidc_cfg.roles_claim = config_result.config.auth.oidc_roles_claim;
            oidc_cfg.user_claim = config_result.config.auth.oidc_user_claim;
            oidc_cfg.jwks_cache_seconds = config_result.config.auth.oidc_jwks_cache_seconds;
            auto oidc_provider = std::make_shared<OidcAuthProvider>(std::move(oidc_cfg));
            g_server->set_auth_provider(oidc_provider);
            utils::log::info(std::format("OIDC auth: enabled (issuer={})",
                config_result.config.auth.oidc_issuer));
        }

        // Wire Protocol Server (PostgreSQL v3)
        if (config_result.success && config_result.config.wire_protocol.enabled) {
            WireProtocolConfig wire_config;
            wire_config.enabled = true;
            wire_config.host = config_result.config.wire_protocol.host;
            wire_config.port = config_result.config.wire_protocol.port;
            wire_config.max_connections = config_result.config.wire_protocol.max_connections;
            wire_config.thread_pool_size = config_result.config.wire_protocol.thread_pool_size;
            wire_config.require_password = config_result.config.wire_protocol.require_password;
            wire_config.prefer_scram = config_result.config.wire_protocol.prefer_scram;
            wire_config.scram_iterations = config_result.config.wire_protocol.scram_iterations;
            wire_config.tls.enabled = config_result.config.wire_protocol.tls.enabled;
            wire_config.tls.cert_file = config_result.config.wire_protocol.tls.cert_file;
            wire_config.tls.key_file = config_result.config.wire_protocol.tls.key_file;
            wire_config.tls.ca_file = config_result.config.wire_protocol.tls.ca_file;
            wire_config.tls.require_client_cert = config_result.config.wire_protocol.tls.require_client_cert;
            g_wire_server = std::make_shared<WireServer>(pipeline, wire_config, users);
            g_wire_server->start();
            utils::log::info(std::format("Wire protocol: listening on {}:{} (auth={})",
                wire_config.host, wire_config.port,
                wire_config.prefer_scram ? "SCRAM-SHA-256" : "cleartext"));
        }

        // Binary RPC Server
        if (config_result.success && config_result.config.binary_rpc.enabled) {
            BinaryRpcConfig rpc_config;
            rpc_config.enabled = true;
            rpc_config.host = config_result.config.binary_rpc.host;
            rpc_config.port = config_result.config.binary_rpc.port;
            rpc_config.max_connections = config_result.config.binary_rpc.max_connections;
            g_binary_rpc_server = std::make_shared<BinaryRpcServer>(pipeline, rpc_config, users);
            g_binary_rpc_server->start();
            utils::log::info(std::format("Binary RPC: listening on {}:{}",
                rpc_config.host, rpc_config.port));
        }

        // =====================================================================
        // [9/9] Config Watcher - hot-reload policies, users, rate limits
        // =====================================================================
        utils::log::info("[9/9] Config watcher initializing...");

        bool watcher_enabled = true;
        int poll_interval = 5;
        if (config_result.success) {
            watcher_enabled = config_result.config.config_watcher.enabled;
            poll_interval = config_result.config.config_watcher.poll_interval_seconds;
        }

        if (watcher_enabled) {
            g_config_watcher = std::make_shared<ConfigWatcher>(
                config_file,
                std::chrono::seconds{poll_interval});

            // Register reload callback — dispatches to each component
            // Captures shared_ptrs to keep components alive
            g_config_watcher->set_callback(
                [policy_engine, rate_limiter, query_rewriter, server = g_server]
                (const ProxyConfig& new_cfg) {

                // 1. Hot-reload policies (RCU — zero-downtime atomic swap)
                policy_engine->reload_policies(new_cfg.policies);
                utils::log::info(std::format("Policies reloaded: {} policies",
                                              new_cfg.policies.size()));

                // 2. Hot-reload users (shared_mutex — readers not blocked)
                server->update_users(new_cfg.users);

                // 3. Hot-reload max SQL length (atomic)
                server->update_max_sql_length(new_cfg.server.max_sql_length);

                // 4. Hot-reload rate limits (per-user/per-db overrides)
                for (const auto& limit : new_cfg.rate_limiting.per_user) {
                    rate_limiter->set_user_limit(
                        limit.user, limit.tokens_per_second, limit.burst_capacity);
                }
                for (const auto& limit : new_cfg.rate_limiting.per_database) {
                    rate_limiter->set_database_limit(
                        limit.database, limit.tokens_per_second, limit.burst_capacity);
                }
                for (const auto& limit : new_cfg.rate_limiting.per_user_per_database) {
                    rate_limiter->set_user_database_limit(
                        limit.user, limit.database, limit.tokens_per_second, limit.burst_capacity);
                }

                // 5. Hot-reload query rewriter rules
                if (query_rewriter) {
                    query_rewriter->reload_rules(new_cfg.rls_rules, new_cfg.rewrite_rules);
                    utils::log::info(std::format("Query rewriter reloaded: {} RLS, {} rewrite",
                        new_cfg.rls_rules.size(), new_cfg.rewrite_rules.size()));
                }
            });

            g_config_watcher->start();
            utils::log::info(std::format("Config watcher: polling every {}s", poll_interval));
        } else {
            utils::log::info("Config watcher: disabled");
        }

        utils::log::info(std::format("Server ready on http://{}:{} ({} users)", host, port, users.size()));

        // Start HTTP server (blocking)
        g_server->start();

    } catch (const std::exception& e) {
        utils::log::error(std::format("Fatal: {}", e.what()));
        return 1;
    }

    return 0;
}
