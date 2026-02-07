#include "core/pipeline.hpp"
#include "core/utils.hpp"
#include "config/config_loader.hpp"
#include "server/http_server.hpp"
#include "parser/sql_parser.hpp"
#include "parser/parse_cache.hpp"
#include "policy/policy_engine.hpp"
#include "policy/policy_loader.hpp"
#include "server/rate_limiter.hpp"
#include "executor/query_executor.hpp"
#include "executor/circuit_breaker.hpp"
#include "executor/connection_pool.hpp"
#include "classifier/classifier_registry.hpp"
#include "audit/audit_emitter.hpp"

#include <memory>
#include <csignal>
#include <cstdlib>

using namespace sqlproxy;

// Global server instance for signal handling
std::shared_ptr<HttpServer> g_server;

void signal_handler(int signal) {
    utils::log::info("Received signal " + std::to_string(signal) + ", shutting down...");
    if (g_server) {
        g_server->stop();
    }
    exit(0);
}

int main(int argc, char* argv[]) {
    try {
        utils::log::info("SQL Proxy Service starting...");

        // Setup signal handlers
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);

        // Configuration
        std::string config_file = "config/proxy.toml";
        if (argc > 1) {
            config_file = argv[1];
        }

        utils::log::info("[1/8] Loading configuration from " + config_file);

        // Try to load full config via ConfigLoader
        auto config_result = ConfigLoader::load_from_file(config_file);

        // Extract config values (or use defaults)
        std::vector<Policy> policies;
        std::unordered_map<std::string, UserInfo> users;
        std::string db_conn_string = "postgresql://proxy_user:secure_password@postgres:5432/testdb";
        std::string audit_file = "logs/audit.jsonl";
        AuditConfig audit_config;

        HierarchicalRateLimiter::Config rate_config;
        CacheConfig cache_config;
        cache_config.max_entries = 10000;
        cache_config.num_shards = 16;

        ConnectionPool::Config pool_config;
        pool_config.connection_string = db_conn_string;
        pool_config.min_connections = 2;
        pool_config.max_connections = 10;
        pool_config.connection_timeout = std::chrono::milliseconds{5000};
        pool_config.health_check_query = "SELECT 1";

        if (config_result.success) {
            const auto& cfg = config_result.config;
            utils::log::info("Config loaded: " + std::to_string(cfg.policies.size())
                + " policies, " + std::to_string(cfg.users.size()) + " users");

            // Policies
            policies = cfg.policies;

            // Users
            users = cfg.users;

            // Database connection
            if (!cfg.databases.empty()) {
                const auto& db = cfg.databases[0];
                db_conn_string = db.connection_string;
                pool_config.connection_string = db.connection_string;
                pool_config.min_connections = db.min_connections;
                pool_config.max_connections = db.max_connections;
                pool_config.connection_timeout = db.connection_timeout;
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
            utils::log::warn(config_result.error_message + " - using hardcoded defaults");

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

        utils::log::info("[2/8] Parse cache: " + std::to_string(cache_config.max_entries)
            + " entries, " + std::to_string(cache_config.num_shards) + " shards");
        auto parse_cache = std::make_shared<ParseCache>(
            cache_config.max_entries, cache_config.num_shards);

        utils::log::info("[3/8] SQL parser: libpg_query ready");
        auto parser = std::make_shared<SQLParser>(parse_cache);

        utils::log::info("[4/8] Policy engine initializing...");
        auto policy_engine = std::make_shared<PolicyEngine>();
        policy_engine->load_policies(policies);
        utils::log::info("Policies: " + std::to_string(policy_engine->policy_count()) + " loaded");

        utils::log::info("[5/8] Rate limiter: 4 levels (Global -> User -> DB -> User+DB)");
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

        utils::log::info("[6/8] Connection pool & executor initializing...");
        std::string db_name = "testdb";
        if (config_result.success && !config_result.config.databases.empty()) {
            db_name = config_result.config.databases[0].name;
        }

        auto circuit_breaker = std::make_shared<CircuitBreaker>(db_name);
        auto pool = std::make_shared<ConnectionPool>(db_name, pool_config, circuit_breaker);

        auto executor = std::make_shared<QueryExecutor>(pool, circuit_breaker);
        utils::log::info("Executor: PostgreSQL libpq with circuit breaker");

        utils::log::info("[7/8] Classifier & audit initializing...");
        auto classifier = std::make_shared<ClassifierRegistry>();
        auto audit_emitter = std::make_shared<AuditEmitter>(audit_file);
        utils::log::info("Audit: writing to " + audit_file);

        utils::log::info("[8/8] Starting HTTP server...");

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

        // Create and start HTTP server
        g_server = std::make_shared<HttpServer>(pipeline, host, port, users);

        utils::log::info("Server ready on http://" + host + ":" + std::to_string(port)
            + " (" + std::to_string(users.size()) + " users)");

        g_server->start();

    } catch (const std::exception& e) {
        utils::log::error(std::string("Fatal: ") + e.what());
        return 1;
    }

    return 0;
}
