#pragma once

#include "core/pipeline.hpp"
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace sqlproxy {

/**
 * @brief User information for authentication
 */
struct UserInfo {
    std::string name;
    std::vector<std::string> roles;
};

/**
 * @brief HTTP server for SQL proxy
 *
 * Routes:
 * - POST /api/v1/query - Execute SELECT queries
 * - POST /api/v1/execute - Execute DML/DDL
 * - GET /health - Health check
 * - GET /metrics - Metrics endpoint
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
     */
    explicit HttpServer(
        std::shared_ptr<Pipeline> pipeline,
        std::string host = "0.0.0.0",
        int port = 8080,
        std::unordered_map<std::string, UserInfo> users = {},
        std::string admin_token = ""
    );

    /**
     * @brief Start server (blocking)
     */
    void start();

    /**
     * @brief Stop server
     */
    void stop();

private:
    /**
     * @brief Validate user exists and resolve roles
     * @return UserInfo if valid, nullopt if unknown user
     */
    std::optional<UserInfo> validate_user(const std::string& username) const;

    std::shared_ptr<Pipeline> pipeline_;
    const std::string host_;
    const int port_;
    const std::unordered_map<std::string, UserInfo> users_;
    const std::string admin_token_;
};

} // namespace sqlproxy
