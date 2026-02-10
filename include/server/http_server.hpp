#pragma once

#include "core/pipeline.hpp"
#include "server/response_compressor.hpp"
#include <atomic>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

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
 * Routes:
 * - POST /api/v1/query - Execute SELECT queries
 * - POST /api/v1/execute - Execute DML/DDL
 * - GET /health - Health check
 * - GET /metrics - Metrics endpoint
 *
 * Hot-reloadable state (via ConfigWatcher):
 * - users_: User registry (shared_mutex protected)
 * - max_sql_length_: Max SQL size (atomic)
 */
class HttpServer {
public:
    /**
     * @brief Construct HTTP server
     * @param pipeline Request pipeline
     * @param host Bind host (default: 0.0.0.0)
     * @param port Bind port (default: 8080)
     * @param users User registry for authentication (optional)
     * @param admin_token Bearer token for admin endpoints (empty = no auth required)
     * @param max_sql_length Max SQL query size in bytes (default: 100KB)
     * @param tls_config TLS/mTLS configuration (default: disabled)
     */
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
        ResponseCompressor::Config compressor_config = ResponseCompressor::Config{}
    );

    /**
     * @brief Start server (blocking)
     */
    void start();

    /**
     * @brief Stop server
     */
    void stop();

    /**
     * @brief Hot-reload users (thread-safe, zero-downtime)
     * In-flight requests use old users; new requests get updated users.
     */
    void update_users(std::unordered_map<std::string, UserInfo> new_users);

    /**
     * @brief Hot-reload max SQL length (thread-safe, atomic)
     */
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
    /**
     * @brief Validate user exists and resolve roles
     * @return UserInfo if valid, nullopt if unknown user
     */
    std::optional<UserInfo> validate_user(const std::string& username) const;

    /**
     * @brief Authenticate via Bearer token
     * @return UserInfo if valid API key, nullopt if invalid
     */
    std::optional<UserInfo> authenticate_api_key(const std::string& api_key) const;

    /**
     * @brief Rebuild API key reverse index (caller must hold unique_lock)
     */
    void rebuild_api_key_index();

    std::shared_ptr<Pipeline> pipeline_;
    const std::string host_;
    const int port_;
    const std::string admin_token_;
    const TlsConfig tls_config_;

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
