#include "core/pipeline.hpp"
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
#include "classifier/classifier_registry.hpp"
#include "audit/audit_emitter.hpp"
#include "core/query_rewriter.hpp"
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
            policies.push_back(allow_select);

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
            policies.push_back(block_ddl);

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

        utils::log::info(std::format("Creating circuit breaker for database: {}", db_name));
        auto circuit_breaker = std::make_shared<CircuitBreaker>(db_name);

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
        auto classifier = std::make_shared<ClassifierRegistry>();
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
        SqlInjectionDetector::Config sqli_config;
        if (config_result.success) {
            sqli_config.enabled = config_result.config.security.injection_detection_enabled;
        }
        auto injection_detector = std::make_shared<SqlInjectionDetector>(sqli_config);
        utils::log::info(std::format("SQL injection detector: {}",
            sqli_config.enabled ? "enabled" : "disabled"));

        // Anomaly Detector
        AnomalyDetector::Config anomaly_config;
        if (config_result.success) {
            anomaly_config.enabled = config_result.config.security.anomaly_detection_enabled;
        }
        auto anomaly_detector = std::make_shared<AnomalyDetector>(anomaly_config);
        utils::log::info(std::format("Anomaly detector: {}",
            anomaly_config.enabled ? "enabled" : "disabled"));

        // Data Lineage Tracker
        LineageTracker::Config lineage_config;
        if (config_result.success) {
            lineage_config.enabled = config_result.config.security.lineage_tracking_enabled;
        }
        auto lineage_tracker = std::make_shared<LineageTracker>(lineage_config);
        utils::log::info(std::format("Lineage tracker: {}",
            lineage_config.enabled ? "enabled" : "disabled"));

        // Column Encryptor (with pluggable key manager)
        std::shared_ptr<ColumnEncryptor> column_encryptor;
        if (config_result.success && config_result.config.encryption.enabled) {
            const auto& enc_cfg = config_result.config.encryption;

            // Key manager factory
            std::shared_ptr<IKeyManager> key_manager;
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
        PluginRegistry plugin_registry;
        if (config_result.success && !config_result.config.plugins.empty()) {
            for (const auto& plugin_cfg : config_result.config.plugins) {
                PluginConfig pc;
                pc.path = plugin_cfg.path;
                pc.type = plugin_cfg.type;
                pc.config = plugin_cfg.config;
                [[maybe_unused]] bool loaded = plugin_registry.load_plugin(pc);
            }
            utils::log::info(std::format("Plugins: {} classifier, {} audit sink",
                plugin_registry.classifier_plugins().size(),
                plugin_registry.audit_sink_plugins().size()));
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

        // Create pipeline (with Tier 5 + Tier B components)
        auto pipeline = std::make_shared<Pipeline>(
            parser,
            policy_engine,
            active_rate_limiter,
            executor,
            classifier,
            audit_emitter,
            query_rewriter,
            nullptr,  // router
            nullptr,  // prepared
            injection_detector,
            anomaly_detector,
            lineage_tracker,
            column_encryptor,
            schema_manager,
            tenant_manager,
            audit_sampler,
            result_cache
        );

        // GraphQL Handler
        std::shared_ptr<GraphQLHandler> graphql_handler;
        if (config_result.success && config_result.config.graphql.enabled) {
            GraphQLConfig gql_config;
            gql_config.enabled = true;
            gql_config.endpoint = config_result.config.graphql.endpoint;
            gql_config.max_query_depth = config_result.config.graphql.max_query_depth;
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
                pipeline, g_alert_evaluator, std::move(dash_users));
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

        // Create HTTP server (with Tier 2 + Tier 5 + Tier B components)
        g_server = std::make_shared<HttpServer>(pipeline, host, port, users,
            config_result.config.server.admin_token, max_sql_length,
            compliance_reporter, lineage_tracker, schema_manager, graphql_handler,
            dashboard_handler, config_result.config.server.tls, compressor_config);

        // Tier B: Graceful shutdown coordinator
        ShutdownCoordinator::Config shutdown_cfg;
        if (config_result.success) {
            shutdown_cfg.shutdown_timeout = std::chrono::milliseconds(
                config_result.config.server.shutdown_timeout_ms);
        }
        g_shutdown = std::make_shared<ShutdownCoordinator>(shutdown_cfg);
        g_server->set_shutdown_coordinator(g_shutdown);

        // Wire Protocol Server (PostgreSQL v3)
        if (config_result.success && config_result.config.wire_protocol.enabled) {
            WireProtocolConfig wire_config;
            wire_config.enabled = true;
            wire_config.host = config_result.config.wire_protocol.host;
            wire_config.port = config_result.config.wire_protocol.port;
            wire_config.max_connections = config_result.config.wire_protocol.max_connections;
            wire_config.thread_pool_size = config_result.config.wire_protocol.thread_pool_size;
            wire_config.require_password = config_result.config.wire_protocol.require_password;
            g_wire_server = std::make_shared<WireServer>(pipeline, wire_config, users);
            g_wire_server->start();
            utils::log::info(std::format("Wire protocol: listening on {}:{}",
                wire_config.host, wire_config.port));
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
