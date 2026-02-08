#include "server/dashboard_handler.hpp"
#include "server/dashboard_html.hpp"
#include "core/pipeline.hpp"
#include "alerting/alert_evaluator.hpp"
#include "server/rate_limiter.hpp"
#include "audit/audit_emitter.hpp"
#include "policy/policy_engine.hpp"
#include "core/utils.hpp"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include "../third_party/cpp-httplib/httplib.h"
#pragma GCC diagnostic pop

#include <format>
#include <string_view>
#include <thread>

namespace sqlproxy {

namespace {

bool check_admin_auth(const httplib::Request& req, const std::string& admin_token) {
    if (admin_token.empty()) return true;
    auto auth = req.get_header_value("Authorization");
    constexpr std::string_view kBearerPrefix = "Bearer ";
    if (auth.size() <= kBearerPrefix.size()) return false;
    return std::string_view(auth).substr(kBearerPrefix.size()) == admin_token;
}

// Also check token from query parameter (for SSE which can't set headers)
bool check_admin_auth_or_param(const httplib::Request& req, const std::string& admin_token) {
    if (admin_token.empty()) return true;
    if (check_admin_auth(req, admin_token)) return true;
    // Check query parameter
    if (req.has_param("token")) {
        return req.get_param_value("token") == admin_token;
    }
    return false;
}

} // anonymous namespace

DashboardHandler::DashboardHandler(
    std::shared_ptr<Pipeline> pipeline,
    std::shared_ptr<AlertEvaluator> alert_evaluator,
    std::vector<DashboardUser> users)
    : pipeline_(std::move(pipeline)),
      alert_evaluator_(std::move(alert_evaluator)),
      users_(std::move(users)) {}

void DashboardHandler::update_users(std::vector<DashboardUser> users) {
    users_ = std::move(users);
}

void DashboardHandler::register_routes(httplib::Server& svr, const std::string& admin_token) {
    static constexpr const char* kJsonContentType = "application/json";

    // GET /dashboard - Serve SPA HTML
    svr.Get("/dashboard", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(kDashboardHtml, "text/html");
    });

    // GET /dashboard/api/stats - Aggregate stats snapshot
    svr.Get("/dashboard/api/stats", [this, &admin_token](const httplib::Request& req, httplib::Response& res) {
        if (!check_admin_auth(req, admin_token)) {
            res.status = 401;
            res.set_content(R"({"error":"Unauthorized"})", kJsonContentType);
            return;
        }

        std::string json = "{";

        // Rate limiter stats
        auto rate_limiter = pipeline_->get_rate_limiter();
        auto* hierarchical_rl = dynamic_cast<HierarchicalRateLimiter*>(rate_limiter.get());
        if (hierarchical_rl) {
            auto rl = hierarchical_rl->get_stats();
            uint64_t total_rejects = rl.global_rejects + rl.user_rejects
                                   + rl.database_rejects + rl.user_database_rejects;
            uint64_t allowed = (rl.total_checks > total_rejects)
                             ? (rl.total_checks - total_rejects) : 0;
            json += std::format(
                "\"requests_allowed\":{},\"requests_blocked\":{},\"rate_limit_rejects\":{},",
                allowed, total_rejects, total_rejects);
        }

        // Audit stats
        auto audit = pipeline_->get_audit_emitter();
        if (audit) {
            auto as = audit->get_stats();
            json += std::format(
                "\"audit_emitted\":{},\"audit_written\":{},\"audit_overflow\":{},\"active_sinks\":{},",
                as.total_emitted, as.total_written, as.overflow_dropped, as.active_sinks);
        }

        // Alert stats
        if (alert_evaluator_) {
            auto als = alert_evaluator_->get_stats();
            json += std::format(
                "\"alert_evaluations\":{},\"alerts_fired\":{},\"alerts_resolved\":{},\"active_alerts\":{},",
                als.evaluations, als.alerts_fired, als.alerts_resolved, als.active_alert_count);
        }

        // Timestamp
        json += std::format("\"timestamp\":\"{}\"}}",
            utils::format_timestamp(std::chrono::system_clock::now()));

        res.set_content(json, kJsonContentType);
    });

    // GET /dashboard/api/policies - List all policies
    svr.Get("/dashboard/api/policies", [this, &admin_token](const httplib::Request& req, httplib::Response& res) {
        if (!check_admin_auth(req, admin_token)) {
            res.status = 401;
            res.set_content(R"({"error":"Unauthorized"})", kJsonContentType);
            return;
        }

        auto pe = pipeline_->get_policy_engine();
        auto policies = pe->get_policies();

        std::string json = "{\"policies\":[";
        for (size_t i = 0; i < policies.size(); ++i) {
            if (i > 0) json += ",";
            const auto& p = policies[i];
            json += std::format(
                "{{\"name\":\"{}\",\"priority\":{},\"action\":\"{}\",\"database\":\"{}\","
                "\"table\":\"{}\",\"users\":[",
                p.name, p.priority, decision_to_string(p.action),
                p.scope.database.value_or("*"), p.scope.table.value_or("*"));
            bool first = true;
            for (const auto& u : p.users) {
                if (!first) json += ",";
                json += std::format("\"{}\"", u);
                first = false;
            }
            json += "],\"roles\":[";
            first = true;
            for (const auto& r : p.roles) {
                if (!first) json += ",";
                json += std::format("\"{}\"", r);
                first = false;
            }
            json += "]}";
        }
        json += std::format("],\"total\":{}}}", policies.size());
        res.set_content(json, kJsonContentType);
    });

    // GET /dashboard/api/users - List all users
    svr.Get("/dashboard/api/users", [this, &admin_token](const httplib::Request& req, httplib::Response& res) {
        if (!check_admin_auth(req, admin_token)) {
            res.status = 401;
            res.set_content(R"({"error":"Unauthorized"})", kJsonContentType);
            return;
        }

        std::string json = "{\"users\":[";
        for (size_t i = 0; i < users_.size(); ++i) {
            if (i > 0) json += ",";
            const auto& u = users_[i];
            json += std::format("{{\"name\":\"{}\",\"roles\":[", u.name);
            for (size_t j = 0; j < u.roles.size(); ++j) {
                if (j > 0) json += ",";
                json += std::format("\"{}\"", u.roles[j]);
            }
            json += "]}";
        }
        json += std::format("],\"total\":{}}}", users_.size());
        res.set_content(json, kJsonContentType);
    });

    // GET /dashboard/api/alerts - Active alerts + history
    svr.Get("/dashboard/api/alerts", [this, &admin_token](const httplib::Request& req, httplib::Response& res) {
        if (!check_admin_auth(req, admin_token)) {
            res.status = 401;
            res.set_content(R"({"error":"Unauthorized"})", kJsonContentType);
            return;
        }

        if (!alert_evaluator_) {
            res.set_content(R"({"active":[],"history":[],"total":0})", kJsonContentType);
            return;
        }

        auto active = alert_evaluator_->active_alerts();
        auto history = alert_evaluator_->alert_history();

        std::string json = "{\"active\":[";
        for (size_t i = 0; i < active.size(); ++i) {
            if (i > 0) json += ",";
            const auto& a = active[i];
            json += std::format(
                "{{\"id\":\"{}\",\"rule_name\":\"{}\",\"severity\":\"{}\","
                "\"message\":\"{}\",\"current_value\":{:.2f},\"threshold\":{:.2f}}}",
                a.id, a.rule_name, a.severity, a.message,
                a.current_value, a.threshold);
        }
        json += "],\"history\":[";
        for (size_t i = 0; i < history.size(); ++i) {
            if (i > 0) json += ",";
            const auto& h = history[i];
            json += std::format(
                "{{\"id\":\"{}\",\"rule_name\":\"{}\",\"severity\":\"{}\","
                "\"resolved\":{}}}",
                h.id, h.rule_name, h.severity, h.resolved ? "true" : "false");
        }
        json += std::format("],\"total\":{}}}", active.size());
        res.set_content(json, kJsonContentType);
    });

    // GET /dashboard/api/metrics/stream - SSE real-time metrics
    svr.Get("/dashboard/api/metrics/stream", [this, &admin_token](const httplib::Request& req, httplib::Response& res) {
        if (!check_admin_auth_or_param(req, admin_token)) {
            res.status = 401;
            res.set_content(R"({"error":"Unauthorized"})", kJsonContentType);
            return;
        }

        res.set_header("Cache-Control", "no-cache");
        res.set_header("X-Accel-Buffering", "no");

        res.set_chunked_content_provider(
            "text/event-stream",
            [this](size_t /*offset*/, httplib::DataSink& sink) {
                for (int i = 0; i < 300; ++i) { // 300 events * 2s = 10 min max
                    std::string json = "{";

                    auto rate_limiter = pipeline_->get_rate_limiter();
                    auto* rl = dynamic_cast<HierarchicalRateLimiter*>(rate_limiter.get());
                    if (rl) {
                        auto stats = rl->get_stats();
                        uint64_t rejects = stats.global_rejects + stats.user_rejects
                                         + stats.database_rejects + stats.user_database_rejects;
                        uint64_t allowed = (stats.total_checks > rejects)
                                         ? (stats.total_checks - rejects) : 0;
                        json += std::format(
                            "\"requests_allowed\":{},\"requests_blocked\":{},\"rate_limit_rejects\":{},",
                            allowed, rejects, rejects);
                    }

                    auto audit = pipeline_->get_audit_emitter();
                    if (audit) {
                        auto as = audit->get_stats();
                        json += std::format(
                            "\"audit_emitted\":{},\"audit_written\":{},\"audit_overflow\":{},",
                            as.total_emitted, as.total_written, as.overflow_dropped);
                    }

                    size_t active_count = 0;
                    if (alert_evaluator_) {
                        active_count = alert_evaluator_->get_stats().active_alert_count;
                    }

                    json += std::format("\"active_alerts\":{},\"timestamp\":\"{}\"}}",
                        active_count,
                        utils::format_timestamp(std::chrono::system_clock::now()));

                    std::string event = std::format("data: {}\n\n", json);
                    if (!sink.write(event.data(), event.size())) {
                        return false; // Client disconnected
                    }

                    std::this_thread::sleep_for(std::chrono::seconds(2));
                }
                return false; // End stream after max events
            }
        );
    });
}

} // namespace sqlproxy
