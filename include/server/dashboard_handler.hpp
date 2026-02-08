#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace httplib { class Server; }

namespace sqlproxy {

class Pipeline;
class AlertEvaluator;

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
 * All routes require admin token authentication.
 */
class DashboardHandler {
public:
    DashboardHandler(
        std::shared_ptr<Pipeline> pipeline,
        std::shared_ptr<AlertEvaluator> alert_evaluator = nullptr,
        std::vector<DashboardUser> users = {});

    void register_routes(httplib::Server& svr, const std::string& admin_token);

    void update_users(std::vector<DashboardUser> users);

private:
    std::shared_ptr<Pipeline> pipeline_;
    std::shared_ptr<AlertEvaluator> alert_evaluator_;
    std::vector<DashboardUser> users_;
};

} // namespace sqlproxy
