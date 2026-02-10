#pragma once

#include "core/pipeline.hpp"
#include "config/config_types.hpp"
#include "server/response_compressor.hpp"
#include <atomic>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

// Forward-declare httplib types (avoids pulling in massive header-only library)
namespace httplib {
struct Request;
struct Response;
class Server;
}

namespace sqlproxy {

// Forward declarations
class ComplianceReporter;
class LineageTracker;
class SchemaManager;
class GraphQLHandler;
class DashboardHandler;
class AlertEvaluator;
class BruteForceProtector;
class ShutdownCoordinator;
class SchemaDriftDetector;

/**
 * @brief User information for authentication
 */
struct UserInfo {
    std::string name;
    std::vector<std::string> roles;
    std::string api_key;                                            // Bearer token (empty = no API key)
    std::unordered_map<std::string, std::string> attributes;        // User attributes for RLS
    std::string default_database;                                   // Default database for routing
    std::vector<std::string> allowed_ips;                           // CIDR ranges (empty = allow all)

    UserInfo() = default;
    UserInfo(std::string n, std::vector<std::string> r)
        : name(std::move(n)), roles(std::move(r)) {}
    UserInfo(std::string n, std::vector<std::string> r, std::string key)
        : name(std::move(n)), roles(std::move(r)), api_key(std::move(key)) {}
};

/**
 * @brief HTTP server for SQL proxy
 *
 * Route paths are config-driven via RouteConfig (loaded from [routes] in TOML).
 * Handler methods are grouped by domain: core, admin, compliance, schema.
 *
 * Hot-reloadable state (via ConfigWatcher):
 * - users_: User registry (shared_mutex protected)
 * - max_sql_length_: Max SQL size (atomic)
 */
class HttpServer {
public:
    explicit HttpServer(
        std::shared_ptr<Pipeline> pipeline,
        std::string host = "0.0.0.0",
        int port = 8080,
        std::unordered_map<std::string, UserInfo> users = {},
        std::string admin_token = "",
        size_t max_sql_length = 102400,
        std::shared_ptr<ComplianceReporter> compliance_reporter = nullptr,
        std::shared_ptr<LineageTracker> lineage_tracker = nullptr,
        std::shared_ptr<SchemaManager> schema_manager = nullptr,
        std::shared_ptr<GraphQLHandler> graphql_handler = nullptr,
        std::shared_ptr<DashboardHandler> dashboard_handler = nullptr,
        TlsConfig tls_config = {},
        ResponseCompressor::Config compressor_config = ResponseCompressor::Config{},
        RouteConfig routes = {},
        FeatureFlags features = {}
    );

    void start();
    void stop();

    struct HttpStats {
        uint64_t auth_rejects;
        uint64_t brute_force_blocks;
        uint64_t ip_blocks;
    };
    [[nodiscard]] static HttpStats get_http_stats();

    void update_users(std::unordered_map<std::string, UserInfo> new_users);
    void update_max_sql_length(size_t new_max) { max_sql_length_.store(new_max); }

    void set_shutdown_coordinator(std::shared_ptr<ShutdownCoordinator> sc) {
        shutdown_coordinator_ = std::move(sc);
    }
    void set_brute_force_protector(std::shared_ptr<BruteForceProtector> bfp) {
        brute_force_protector_ = std::move(bfp);
    }
    void set_schema_drift_detector(std::shared_ptr<SchemaDriftDetector> sdd) {
        schema_drift_detector_ = std::move(sdd);
    }

private:
    // ── Authentication ──────────────────────────────────────────────────
    std::optional<UserInfo> validate_user(const std::string& username) const;
    std::optional<UserInfo> authenticate_api_key(const std::string& api_key) const;
    void rebuild_api_key_index();

    // ── Route registration (called from start()) ────────────────────────
    void register_core_routes(httplib::Server& svr);
    void register_admin_routes(httplib::Server& svr);
    void register_compliance_routes(httplib::Server& svr);
    void register_schema_routes(httplib::Server& svr);
    void register_optional_routes(httplib::Server& svr);

    // ── Handler methods (one per endpoint) ──────────────────────────────
    void handle_query(const httplib::Request& req, httplib::Response& res);
    void handle_dry_run(const httplib::Request& req, httplib::Response& res);
    void handle_health(const httplib::Request& req, httplib::Response& res);
    void handle_metrics(const httplib::Request& req, httplib::Response& res);
    void handle_policies_reload(const httplib::Request& req, httplib::Response& res);
    void handle_config_validate(const httplib::Request& req, httplib::Response& res);
    void handle_slow_queries(const httplib::Request& req, httplib::Response& res);
    void handle_circuit_breakers(const httplib::Request& req, httplib::Response& res);
    void handle_pii_report(const httplib::Request& req, httplib::Response& res);
    void handle_security_summary(const httplib::Request& req, httplib::Response& res);
    void handle_lineage(const httplib::Request& req, httplib::Response& res);
    void handle_data_subject_access(const httplib::Request& req, httplib::Response& res);
    void handle_schema_history(const httplib::Request& req, httplib::Response& res);
    void handle_schema_pending(const httplib::Request& req, httplib::Response& res);
    void handle_schema_approve(const httplib::Request& req, httplib::Response& res);
    void handle_schema_reject(const httplib::Request& req, httplib::Response& res);
    void handle_schema_drift(const httplib::Request& req, httplib::Response& res);
    void handle_graphql(const httplib::Request& req, httplib::Response& res);

    // ── Helpers ─────────────────────────────────────────────────────────
    std::string build_metrics_output();

    // ── Members ─────────────────────────────────────────────────────────
    std::shared_ptr<Pipeline> pipeline_;
    const std::string host_;
    const int port_;
    const std::string admin_token_;
    const TlsConfig tls_config_;
    const RouteConfig routes_;
    const FeatureFlags features_;

    // Hot-reloadable state
    std::unordered_map<std::string, UserInfo> users_;
    std::unordered_map<std::string, std::string> api_key_index_; // api_key → username
    mutable std::shared_mutex users_mutex_;
    std::atomic<size_t> max_sql_length_;

    // Compliance components (optional)
    std::shared_ptr<ComplianceReporter> compliance_reporter_;
    std::shared_ptr<LineageTracker> lineage_tracker_;
    std::shared_ptr<SchemaManager> schema_manager_;
    std::shared_ptr<GraphQLHandler> graphql_handler_;
    std::shared_ptr<DashboardHandler> dashboard_handler_;

    // Tier B: Shutdown + Compression
    std::shared_ptr<ShutdownCoordinator> shutdown_coordinator_;
    ResponseCompressor compressor_;

    // Tier E: Brute force protection
    std::shared_ptr<BruteForceProtector> brute_force_protector_;

    // Tier F: Schema drift detector
    std::shared_ptr<SchemaDriftDetector> schema_drift_detector_;
};

} // namespace sqlproxy
