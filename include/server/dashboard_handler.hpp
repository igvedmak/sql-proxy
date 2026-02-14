#pragma once

#include "config/config_types.hpp"

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace httplib { class Server; class Request; class Response; }

namespace sqlproxy {

class Pipeline;
class AlertEvaluator;
class SchemaCache;

/// Minimal user info for dashboard display (avoids pulling in http_server.hpp)
struct DashboardUser {
    std::string name;
    std::vector<std::string> roles;
};

/**
 * @brief Admin dashboard handler
 *
 * Serves an embedded single-page web UI and provides JSON API
 * endpoints for real-time metrics, policy/user listing, and alert
 * management. Uses SSE (Server-Sent Events) for streaming metrics.
 *
 * Route paths are config-driven via RouteConfig.
 * All API routes require admin token authentication.
 */
class DashboardHandler {
public:
    DashboardHandler(
        std::shared_ptr<Pipeline> pipeline,
        std::shared_ptr<AlertEvaluator> alert_evaluator = nullptr,
        std::vector<DashboardUser> users = {},
        RouteConfig routes = {},
        std::shared_ptr<SchemaCache> schema_cache = nullptr);

    void register_routes(httplib::Server& svr, const std::string& admin_token);

    void update_users(std::vector<DashboardUser> users);

private:
    // Individual route handlers
    void handle_dashboard_page(const httplib::Request& req, httplib::Response& res);
    void handle_stats(const httplib::Request& req, httplib::Response& res);
    void handle_policies(const httplib::Request& req, httplib::Response& res);
    void handle_users(const httplib::Request& req, httplib::Response& res);
    void handle_alerts(const httplib::Request& req, httplib::Response& res);
    void handle_metrics_stream(const httplib::Request& req, httplib::Response& res);
    void handle_schema(const httplib::Request& req, httplib::Response& res);
    void handle_playground_page(const httplib::Request& req, httplib::Response& res);

    std::shared_ptr<Pipeline> pipeline_;
    std::shared_ptr<AlertEvaluator> alert_evaluator_;
    std::vector<DashboardUser> users_;
    const RouteConfig routes_;
    std::string admin_token_;
    std::shared_ptr<SchemaCache> schema_cache_;
};

} // namespace sqlproxy
