#include "server/http_server.hpp"
#include "audit/audit_emitter.hpp"
#include "core/utils.hpp"
#include "policy/policy_loader.hpp"

// cpp-httplib is header-only
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../third_party/cpp-httplib/httplib.h"

#include <format>
#include <string_view>

namespace sqlproxy {

// Simple JSON parsing/building (would use glaze in production)
namespace {
    std::string_view parse_json_field(std::string_view json, std::string_view field) {
        // Optimized: find "field": pattern without creating temporary string
        char quote_char = '"';
        
        // Search for "field" - build search pattern dynamically in stack
        size_t pos = 0;
        while ((pos = json.find(quote_char, pos)) != std::string_view::npos) {
            // Check if this matches our field
            if (pos + field.size() + 1 < json.size() &&
                json.substr(pos + 1, field.size()) == field &&
                json[pos + field.size() + 1] == quote_char) {
                
                // Found "field", now find the value
                pos += field.size() + 2;
                pos = json.find(quote_char, pos); // Skip colon and whitespace to opening quote
                if (pos == std::string_view::npos) return "";
                
                // Find closing quote
                size_t end = json.find(quote_char, pos + 1);
                if (end == std::string_view::npos) return "";
                
                return json.substr(pos + 1, end - pos - 1);
            }
            ++pos;
        }
        return "";
    }

    std::string build_json_response(const ProxyResponse& response) {
        std::string result_str;
        result_str += std::format("{{\"success\":{},\"audit_id\":\"{}\",",
                                  response.success ? "true" : "false",
                                  response.audit_id);

        if (response.success && response.result.has_value()) {
            const auto& result = *response.result;
            result_str += "\"data\":{\"columns\":[";
            for (size_t i = 0; i < result.column_names.size(); ++i) {
                if (i > 0) result_str += ",";
                result_str += std::format("\"{}\"", result.column_names[i]);
            }
            result_str += "],\"rows\":[";
            for (size_t i = 0; i < result.rows.size(); ++i) {
                if (i > 0) result_str += ",";
                result_str += "[";
                for (size_t j = 0; j < result.rows[i].size(); ++j) {
                    if (j > 0) result_str += ",";
                    result_str += std::format("\"{}\"", result.rows[i][j]);
                }
                result_str += "]";
            }
            result_str += "]},\"classifications\":{";
            bool first = true;
            for (const auto& [col, type] : response.classifications) {
                if (!first) result_str += ",";
                first = false;
                result_str += std::format("\"{}\": \"{}\"", col, type);
            }
            result_str += "},";
        } else {
            result_str += std::format("\"error_code\":\"{}\",\"error_message\":\"{}\",",
                                      error_code_to_string(response.error_code),
                                      response.error_message);
        }

        result_str += std::format("\"execution_time_us\":{}}}", response.execution_time_ms.count());

        return result_str;
    }
}

HttpServer::HttpServer(
    std::shared_ptr<Pipeline> pipeline,
    std::string host,
    int port,
    std::unordered_map<std::string, UserInfo> users)
    : pipeline_(std::move(pipeline)),
      host_(std::move(host)),
      port_(port),
      users_(std::move(users)) {}

std::optional<UserInfo> HttpServer::validate_user(const std::string& username) const {
    auto it = users_.find(username);
    if (it != users_.end()) {
        return it->second;
    }

    // If no users configured, allow all users (development mode)
    if (users_.empty()) {
        UserInfo default_user;
        default_user.name = username;
        default_user.roles = {"user"};  // Default role
        return default_user;
    }

    return std::nullopt;  // User not found
}

void HttpServer::start() {
    httplib::Server svr;

    // POST /api/v1/query - Execute SELECT queries
    svr.Post("/api/v1/query", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            // Validate Content-Type
            std::string content_type = req.get_header_value("Content-Type");
            if (content_type.find("application/json") == std::string_view::npos) {
                res.status = 400;
                res.set_content(R"({"success":false,"error":"Content-Type must be application/json"})", "application/json");
                return;
            }

            // Basic JSON validation - check for opening/closing braces
            std::string_view body = req.body;
            if (body.empty() || body.find('{') == std::string_view::npos || body.find('}') == std::string_view::npos) {
                res.status = 400;
                res.set_content(R"({"success":false,"error":"Invalid JSON: empty or malformed"})", "application/json");
                return;
            }

            // Parse request fields as string_view (zero-copy until validation passes)
            auto user_sv = parse_json_field(req.body, "user");
            auto sql_sv = parse_json_field(req.body, "sql");
            auto database_sv = parse_json_field(req.body, "database");

            // Validate required field: user
            if (user_sv.empty()) {
                res.status = 400;
                res.set_content(R"({"success":false,"error":"Missing required field: user"})", "application/json");
                return;
            }

            // Validate required field: sql
            if (sql_sv.empty()) {
                res.status = 400;
                res.set_content(R"({"success":false,"error":"Missing required field: sql"})", "application/json");
                return;
            }

            // Validate SQL length (max 100KB)
            constexpr size_t MAX_SQL_LENGTH = 100 * 1024;
            if (sql_sv.length() > MAX_SQL_LENGTH) {
                res.status = 400;
                res.set_content(
                    std::format(R"({{"success":false,"error":"SQL too long: max {} bytes"}})", MAX_SQL_LENGTH),
                    "application/json");
                return;
            }

            // Convert to owning strings only after validation passes
            std::string user(user_sv);
            std::string sql(sql_sv);
            std::string database = database_sv.empty()
                ? std::string("testdb")
                : std::string(database_sv);

            // Authenticate user and resolve roles
            auto user_info = validate_user(user);
            if (!user_info.has_value()) {
                res.status = 401;
                res.set_content(
                    std::format(R"({{"success":false,"error":"Unknown user: {}"}})", user_sv),
                    "application/json");
                return;
            }

            // Build proxy request
            ProxyRequest proxy_req;
            proxy_req.request_id = utils::generate_uuid();
            proxy_req.user = user;
            proxy_req.roles = user_info->roles;  // Add resolved roles
            proxy_req.sql = sql;
            proxy_req.database = database;
            proxy_req.source_ip = req.get_header_value("X-Forwarded-For");
            if (proxy_req.source_ip.empty()) {
                proxy_req.source_ip = req.remote_addr;
            }

            // Execute through pipeline
            auto response = pipeline_->execute(proxy_req);

            // Build JSON response
            std::string json = build_json_response(response);

            // Set HTTP status
            if (response.success) {
                res.status = 200;
            } else {
                // O(1) lookup: ErrorCode enum index → HTTP status
                static constexpr int kErrorToHttp[] = {
                    200,  // NONE
                    400,  // PARSE_ERROR
                    403,  // ACCESS_DENIED
                    429,  // RATE_LIMITED
                    503,  // CIRCUIT_OPEN
                    502,  // DATABASE_ERROR
                    500,  // INTERNAL_ERROR
                    400,  // INVALID_REQUEST
                    413,  // RESULT_TOO_LARGE
                };
                auto idx = static_cast<size_t>(response.error_code);
                res.status = (idx < std::size(kErrorToHttp))
                    ? kErrorToHttp[idx]
                    : 500;
            }

            res.set_content(json, "application/json");

        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(
                std::format(R"({{"success":false,"error":"{}"}})", e.what()),
                "application/json");
        }
    });

    // GET /health - Health check
    svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        std::string health_json = R"({"status":"healthy","service":"sql-proxy"})";
        res.set_content(health_json, "application/json");
    });

    // GET /metrics - Prometheus metrics endpoint
    svr.Get("/metrics", [this](const httplib::Request&, httplib::Response& res) {
        std::ostringstream oss;

        // --- Rate limiter stats ---
        auto rate_limiter = pipeline_->get_rate_limiter();
        if (rate_limiter) {
            auto rl_stats = rate_limiter->get_stats();

            // Total requests (allowed = total - all rejects)
            uint64_t total_rejects = rl_stats.global_rejects
                                   + rl_stats.user_rejects
                                   + rl_stats.database_rejects
                                   + rl_stats.user_database_rejects;
            uint64_t total_allowed = (rl_stats.total_checks > total_rejects)
                                   ? (rl_stats.total_checks - total_rejects)
                                   : 0;

            oss << "# HELP sql_proxy_requests_total Total number of requests processed\n";
            oss << "# TYPE sql_proxy_requests_total counter\n";
            oss << "sql_proxy_requests_total{status=\"allowed\"} " << total_allowed << "\n";
            oss << "sql_proxy_requests_total{status=\"blocked\"} " << total_rejects << "\n";
            oss << "\n";

            // Per-level rate limit rejects
            oss << "# HELP sql_proxy_rate_limit_total Rate limit rejections by level\n";
            oss << "# TYPE sql_proxy_rate_limit_total counter\n";
            oss << "sql_proxy_rate_limit_total{level=\"global\"} " << rl_stats.global_rejects << "\n";
            oss << "sql_proxy_rate_limit_total{level=\"user\"} " << rl_stats.user_rejects << "\n";
            oss << "sql_proxy_rate_limit_total{level=\"database\"} " << rl_stats.database_rejects << "\n";
            oss << "sql_proxy_rate_limit_total{level=\"user_database\"} " << rl_stats.user_database_rejects << "\n";
            oss << "\n";

            // Total rate limit checks
            oss << "# HELP sql_proxy_rate_limit_checks_total Total rate limit checks performed\n";
            oss << "# TYPE sql_proxy_rate_limit_checks_total counter\n";
            oss << "sql_proxy_rate_limit_checks_total " << rl_stats.total_checks << "\n";
            oss << "\n";
        }

        // --- Audit emitter stats ---
        auto audit_emitter = pipeline_->get_audit_emitter();
        if (audit_emitter) {
            auto audit_stats = audit_emitter->get_stats();

            oss << "# HELP sql_proxy_audit_emitted_total Audit records pushed to ring buffer\n";
            oss << "# TYPE sql_proxy_audit_emitted_total counter\n";
            oss << "sql_proxy_audit_emitted_total " << audit_stats.total_emitted << "\n";
            oss << "\n";

            oss << "# HELP sql_proxy_audit_written_total Audit records written to file\n";
            oss << "# TYPE sql_proxy_audit_written_total counter\n";
            oss << "sql_proxy_audit_written_total " << audit_stats.total_written << "\n";
            oss << "\n";

            oss << "# HELP sql_proxy_audit_dropped_total Audit records dropped due to buffer overflow\n";
            oss << "# TYPE sql_proxy_audit_dropped_total counter\n";
            oss << "sql_proxy_audit_dropped_total " << audit_stats.overflow_dropped << "\n";
            oss << "\n";

            oss << "# HELP sql_proxy_audit_flushes_total Number of batch flushes performed\n";
            oss << "# TYPE sql_proxy_audit_flushes_total counter\n";
            oss << "sql_proxy_audit_flushes_total " << audit_stats.flush_count << "\n";
            oss << "\n";
        }

        // --- Build info ---
        oss << "# HELP sql_proxy_info Build information\n";
        oss << "# TYPE sql_proxy_info gauge\n";
        oss << "sql_proxy_info{version=\"1.0.0\"} 1\n";

        res.set_content(oss.str(), "text/plain; version=0.0.4; charset=utf-8");
    });

    // POST /policies/reload - Hot reload policies from config file
    svr.Post("/policies/reload", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            // Optional: Check authorization
            std::string auth = req.get_header_value("Authorization");
            // TODO: Validate auth token if needed

            // Load policies from config file
            std::string config_path = "config/proxy.toml";
            auto load_result = PolicyLoader::load_from_file(config_path);

            if (!load_result.success) {
                res.status = 400;
                res.set_content(
                    std::format(R"({{"success":false,"error":"{}"}})", load_result.error_message),
                    "application/json");
                return;
            }

            // Hot reload policies via RCU (zero downtime)
            pipeline_->get_policy_engine()->reload_policies(load_result.policies);

            // Success response
            res.status = 200;
            res.set_content(
                std::format(R"({{"success":true,"policies_loaded":{}}})", load_result.policies.size()),
                "application/json");

            utils::log::info(std::format("Policies reloaded: {} policies loaded", load_result.policies.size()));

        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(
                std::format(R"({{"success":false,"error":"{}"}})", e.what()),
                "application/json");
        }
    });

    utils::log::info("Starting SQL Proxy Server on " + host_ + ":" + std::to_string(port_));
    utils::log::info("Endpoints: POST /api/v1/query, GET /health, GET /metrics, POST /policies/reload");

    if (!svr.listen(host_.c_str(), port_)) {
        throw std::runtime_error("Failed to start HTTP server");
    }
}

void HttpServer::stop() {
    utils::log::info("Server stopped");
}

} // namespace sqlproxy
