#include "server/dashboard_handler.hpp"
#include "server/dashboard_html.hpp"
#include "server/http_constants.hpp"
#include "server/http_server.hpp"
#include "core/pipeline.hpp"
#include "alerting/alert_evaluator.hpp"
#include "server/rate_limiter.hpp"
#include "audit/audit_emitter.hpp"
#include "policy/policy_engine.hpp"
#include "analyzer/schema_cache.hpp"
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
    const auto auth = req.get_header_value(http::kAuthorizationHeader);
    if (auth.size() <= http::kBearerPrefix.size()) return false;
    return std::string_view(auth).substr(http::kBearerPrefix.size()) == admin_token;
}

// Also check token from query parameter (for SSE which can't set headers)
bool check_admin_auth_or_param(const httplib::Request& req, const std::string& admin_token) {
    if (admin_token.empty()) return true;
    if (check_admin_auth(req, admin_token)) return true;
    if (req.has_param("token")) {
        return req.get_param_value("token") == admin_token;
    }
    return false;
}

} // anonymous namespace

// ============================================================================
// Constructor
// ============================================================================

DashboardHandler::DashboardHandler(
    std::shared_ptr<Pipeline> pipeline,
    std::shared_ptr<AlertEvaluator> alert_evaluator,
    std::vector<DashboardUser> users,
    RouteConfig routes,
    std::shared_ptr<SchemaCache> schema_cache)
    : pipeline_(std::move(pipeline)),
      alert_evaluator_(std::move(alert_evaluator)),
      users_(std::move(users)),
      routes_(std::move(routes)),
      schema_cache_(std::move(schema_cache)) {}

void DashboardHandler::update_users(std::vector<DashboardUser> users) {
    users_ = std::move(users);
}

// ============================================================================
// Route registration
// ============================================================================

void DashboardHandler::register_routes(httplib::Server& svr, const std::string& admin_token) {
    admin_token_ = admin_token;

    svr.Get(routes_.dashboard, [this](const httplib::Request& req, httplib::Response& res) {
        handle_dashboard_page(req, res);
    });
    svr.Get(routes_.dashboard_stats, [this](const httplib::Request& req, httplib::Response& res) {
        handle_stats(req, res);
    });
    svr.Get(routes_.dashboard_policies, [this](const httplib::Request& req, httplib::Response& res) {
        handle_policies(req, res);
    });
    svr.Get(routes_.dashboard_users, [this](const httplib::Request& req, httplib::Response& res) {
        handle_users(req, res);
    });
    svr.Get(routes_.dashboard_alerts, [this](const httplib::Request& req, httplib::Response& res) {
        handle_alerts(req, res);
    });
    svr.Get(routes_.dashboard_stream, [this](const httplib::Request& req, httplib::Response& res) {
        handle_metrics_stream(req, res);
    });
    svr.Get(routes_.dashboard + "/api/schema", [this](const httplib::Request& req, httplib::Response& res) {
        handle_schema(req, res);
    });
    svr.Get(routes_.dashboard + "/playground", [this](const httplib::Request& req, httplib::Response& res) {
        handle_playground_page(req, res);
    });
}

// ============================================================================
// Handler: GET /dashboard
// ============================================================================

void DashboardHandler::handle_dashboard_page(const httplib::Request&, httplib::Response& res) {
    res.set_content(kDashboardHtml, "text/html");
}

// ============================================================================
// Handler: GET /dashboard/api/stats
// ============================================================================

void DashboardHandler::handle_stats(const httplib::Request& req, httplib::Response& res) {
    if (!check_admin_auth(req, admin_token_)) {
        res.status = httplib::StatusCode::Unauthorized_401;
        res.set_content(R"({"error":"Unauthorized"})", http::kJsonContentType);
        return;
    }

    std::string json = "{";

    const auto ps = pipeline_->get_stats();
    const uint64_t allowed = (ps.total_requests > ps.requests_blocked)
                     ? (ps.total_requests - ps.requests_blocked) : 0;

    uint64_t rate_limit_rejects = 0;
    auto rate_limiter = pipeline_->get_rate_limiter();
    auto* hierarchical_rl = dynamic_cast<HierarchicalRateLimiter*>(rate_limiter.get());
    if (hierarchical_rl) {
        const auto rl = hierarchical_rl->get_stats();
        rate_limit_rejects = rl.global_rejects + rl.user_rejects
                           + rl.database_rejects + rl.user_database_rejects;
    }

    const auto hs = HttpServer::get_http_stats();

    json += std::format(
        "\"requests_allowed\":{},\"requests_blocked\":{},\"rate_limit_rejects\":{},"
        "\"auth_rejects\":{},\"brute_force_blocks\":{},\"ip_blocks\":{},",
        allowed, ps.requests_blocked, rate_limit_rejects,
        hs.auth_rejects, hs.brute_force_blocks, hs.ip_blocks);

    const auto audit = pipeline_->get_audit_emitter();
    if (audit) {
        const auto as = audit->get_stats();
        json += std::format(
            "\"audit_emitted\":{},\"audit_written\":{},\"audit_overflow\":{},\"active_sinks\":{},",
            as.total_emitted, as.total_written, as.overflow_dropped, as.active_sinks);
    }

    if (alert_evaluator_) {
        const auto als = alert_evaluator_->get_stats();
        json += std::format(
            "\"alert_evaluations\":{},\"alerts_fired\":{},\"alerts_resolved\":{},\"active_alerts\":{},",
            als.evaluations, als.alerts_fired, als.alerts_resolved, als.active_alert_count);
    }

    json += std::format("\"timestamp\":\"{}\"}}",
        utils::format_timestamp(std::chrono::system_clock::now()));

    res.set_content(json, http::kJsonContentType);
}

// ============================================================================
// Handler: GET /dashboard/api/policies
// ============================================================================

void DashboardHandler::handle_policies(const httplib::Request& req, httplib::Response& res) {
    if (!check_admin_auth(req, admin_token_)) {
        res.status = httplib::StatusCode::Unauthorized_401;
        res.set_content(R"({"error":"Unauthorized"})", http::kJsonContentType);
        return;
    }

    const auto pe = pipeline_->get_policy_engine();
    const auto policies = pe->get_policies();

    std::string json = "{\"policies\":[";
    for (size_t i = 0; i < policies.size(); ++i) {
        if (i > 0) json += ",";
        const auto& p = policies[i];
        json += std::format(
            "{{\"name\":\"{}\",\"priority\":{},\"action\":\"{}\",\"database\":\"{}\","
            "\"table\":\"{}\",\"users\":[",
            utils::escape_json(p.name), p.priority, decision_to_string(p.action),
            utils::escape_json(p.scope.database.value_or("*")),
            utils::escape_json(p.scope.table.value_or("*")));
        bool first = true;
        for (const auto& u : p.users) {
            if (!first) json += ",";
            json += std::format("\"{}\"", utils::escape_json(u));
            first = false;
        }
        json += "],\"roles\":[";
        first = true;
        for (const auto& r : p.roles) {
            if (!first) json += ",";
            json += std::format("\"{}\"", utils::escape_json(r));
            first = false;
        }
        json += "]}";
    }
    json += std::format("],\"total\":{}}}", policies.size());
    res.set_content(json, http::kJsonContentType);
}

// ============================================================================
// Handler: GET /dashboard/api/users
// ============================================================================

void DashboardHandler::handle_users(const httplib::Request& req, httplib::Response& res) {
    if (!check_admin_auth(req, admin_token_)) {
        res.status = httplib::StatusCode::Unauthorized_401;
        res.set_content(R"({"error":"Unauthorized"})", http::kJsonContentType);
        return;
    }

    std::string json = "{\"users\":[";
    for (size_t i = 0; i < users_.size(); ++i) {
        if (i > 0) json += ",";
        const auto& u = users_[i];
        json += std::format("{{\"name\":\"{}\",\"roles\":[", utils::escape_json(u.name));
        for (size_t j = 0; j < u.roles.size(); ++j) {
            if (j > 0) json += ",";
            json += std::format("\"{}\"", utils::escape_json(u.roles[j]));
        }
        json += "]}";
    }
    json += std::format("],\"total\":{}}}", users_.size());
    res.set_content(json, http::kJsonContentType);
}

// ============================================================================
// Handler: GET /dashboard/api/alerts
// ============================================================================

void DashboardHandler::handle_alerts(const httplib::Request& req, httplib::Response& res) {
    if (!check_admin_auth(req, admin_token_)) {
        res.status = httplib::StatusCode::Unauthorized_401;
        res.set_content(R"({"error":"Unauthorized"})", http::kJsonContentType);
        return;
    }

    if (!alert_evaluator_) {
        res.set_content(R"({"active":[],"history":[],"total":0})", http::kJsonContentType);
        return;
    }

    const auto active = alert_evaluator_->active_alerts();
    const auto history = alert_evaluator_->alert_history();

    std::string json = "{\"active\":[";
    for (size_t i = 0; i < active.size(); ++i) {
        if (i > 0) json += ",";
        const auto& a = active[i];
        json += std::format(
            "{{\"id\":\"{}\",\"rule_name\":\"{}\",\"severity\":\"{}\","
            "\"message\":\"{}\",\"current_value\":{:.2f},\"threshold\":{:.2f}}}",
            utils::escape_json(a.id), utils::escape_json(a.rule_name),
            utils::escape_json(a.severity), utils::escape_json(a.message),
            a.current_value, a.threshold);
    }
    json += "],\"history\":[";
    for (size_t i = 0; i < history.size(); ++i) {
        if (i > 0) json += ",";
        const auto& h = history[i];
        json += std::format(
            "{{\"id\":\"{}\",\"rule_name\":\"{}\",\"severity\":\"{}\","
            "\"resolved\":{}}}",
            utils::escape_json(h.id), utils::escape_json(h.rule_name),
            utils::escape_json(h.severity), utils::booltostr(h.resolved));
    }
    json += std::format("],\"total\":{}}}", active.size());
    res.set_content(json, http::kJsonContentType);
}

// ============================================================================
// Handler: GET /dashboard/api/metrics/stream (SSE)
// ============================================================================

void DashboardHandler::handle_metrics_stream(const httplib::Request& req, httplib::Response& res) {
    if (!check_admin_auth_or_param(req, admin_token_)) {
        res.status = httplib::StatusCode::Unauthorized_401;
        res.set_content(R"({"error":"Unauthorized"})", http::kJsonContentType);
        return;
    }

    res.set_header("Cache-Control", "no-cache");
    res.set_header("X-Accel-Buffering", "no");

    res.set_chunked_content_provider(
        "text/event-stream",
        [this](size_t /*offset*/, httplib::DataSink& sink) {
            for (int i = 0; i < 300; ++i) { // 300 events * 2s = 10 min max
                std::string json = "{";

                const auto ps = pipeline_->get_stats();
                const uint64_t allowed = (ps.total_requests > ps.requests_blocked)
                                 ? (ps.total_requests - ps.requests_blocked) : 0;

                uint64_t rate_limit_rejects = 0;
                const auto rate_limiter = pipeline_->get_rate_limiter();
                auto* rl = dynamic_cast<HierarchicalRateLimiter*>(rate_limiter.get());
                if (rl) {
                    const auto stats = rl->get_stats();
                    rate_limit_rejects = stats.global_rejects + stats.user_rejects
                                       + stats.database_rejects + stats.user_database_rejects;
                }

                const auto hs = HttpServer::get_http_stats();

                json += std::format(
                    "\"requests_allowed\":{},\"requests_blocked\":{},\"rate_limit_rejects\":{},"
                    "\"auth_rejects\":{},\"brute_force_blocks\":{},\"ip_blocks\":{},",
                    allowed, ps.requests_blocked, rate_limit_rejects,
                    hs.auth_rejects, hs.brute_force_blocks, hs.ip_blocks);

                const auto audit = pipeline_->get_audit_emitter();
                if (audit) {
                    const auto as = audit->get_stats();
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

                const std::string event = std::format("data: {}\n\n", json);
                if (!sink.write(event.data(), event.size())) {
                    return false; // Client disconnected
                }

                std::this_thread::sleep_for(std::chrono::seconds(2));
            }
            return false; // End stream after max events
        }
    );
}

// ============================================================================
// Handler: GET /dashboard/api/schema
// ============================================================================

void DashboardHandler::handle_schema(const httplib::Request& req, httplib::Response& res) {
    if (!check_admin_auth(req, admin_token_)) {
        res.status = httplib::StatusCode::Unauthorized_401;
        res.set_content(R"({"error":"Unauthorized"})", http::kJsonContentType);
        return;
    }

    if (!schema_cache_) {
        res.set_content(R"({"tables":[]})", http::kJsonContentType);
        return;
    }

    auto tables = schema_cache_->get_all_tables();

    std::string json = "{\"tables\":[";
    bool first_table = true;
    for (const auto& [name, meta] : tables) {
        if (!first_table) json += ',';
        first_table = false;

        json += std::format("{{\"name\":\"{}\",\"schema\":\"{}\",\"columns\":[",
                            utils::escape_json(meta->name), utils::escape_json(meta->schema));

        for (size_t i = 0; i < meta->columns.size(); ++i) {
            if (i > 0) json += ',';
            const auto& col = meta->columns[i];
            json += std::format(
                "{{\"name\":\"{}\",\"type\":\"{}\",\"nullable\":{},\"primary_key\":{}}}",
                utils::escape_json(col.name), utils::escape_json(col.type),
                utils::booltostr(col.nullable),
                utils::booltostr(col.is_primary_key));
        }
        json += "]}";
    }
    json += "]}";

    res.set_content(json, http::kJsonContentType);
}

// ============================================================================
// Handler: GET /dashboard/playground
// ============================================================================

void DashboardHandler::handle_playground_page(const httplib::Request&, httplib::Response& res) {
    res.set_content(kPlaygroundHtml, "text/html");
}

} // namespace sqlproxy
