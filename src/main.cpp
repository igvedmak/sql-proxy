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
    if (g_config_watcher) {
        g_config_watcher->stop();
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
        auto audit_emitter = std::make_shared<AuditEmitter>(audit_file);
        utils::log::info(std::format("Audit: writing to {}", audit_file));

        // Create pipeline
        auto pipeline = std::make_shared<Pipeline>(
            parser,
            policy_engine,
            rate_limiter,
            executor,
            classifier,
            audit_emitter
        );

        // Determine server bind address and port
        std::string host = "0.0.0.0";
        uint16_t port = 8080;
        if (config_result.success) {
            host = config_result.config.server.host;
            port = config_result.config.server.port;
        }

        // Create HTTP server
        g_server = std::make_shared<HttpServer>(pipeline, host, port, users,
            config_result.config.server.admin_token, max_sql_length);

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
                [policy_engine, rate_limiter, server = g_server]
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
