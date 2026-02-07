#include "server/http_server.hpp"
#include "audit/audit_emitter.hpp"
#include "core/utils.hpp"
#include "policy/policy_loader.hpp"

// cpp-httplib is header-only — suppress its internal deprecation warnings
#define CPPHTTPLIB_OPENSSL_SUPPORT
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include "../third_party/cpp-httplib/httplib.h"
#pragma GCC diagnostic pop

#include <format>
#include <string_view>

namespace sqlproxy {

static constexpr const char* kJsonContentType = "application/json";

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

            // Masked columns
            if (!response.masked_columns.empty()) {
                result_str += "\"masked_columns\":[";
                for (size_t i = 0; i < response.masked_columns.size(); ++i) {
                    if (i > 0) result_str += ",";
                    result_str += std::format("\"{}\"", response.masked_columns[i]);
                }
                result_str += "],";
            }

            // Blocked columns
            if (!response.blocked_columns.empty()) {
                result_str += "\"blocked_columns\":[";
                for (size_t i = 0; i < response.blocked_columns.size(); ++i) {
                    if (i > 0) result_str += ",";
                    result_str += std::format("\"{}\"", response.blocked_columns[i]);
                }
                result_str += "],";
            }
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
    std::unordered_map<std::string, UserInfo> users,
    std::string admin_token,
    size_t max_sql_length)
    : pipeline_(std::move(pipeline)),
      host_(std::move(host)),
      port_(port),
      admin_token_(std::move(admin_token)),
      users_(std::move(users)),
      max_sql_length_(max_sql_length) {
    rebuild_api_key_index();
}

std::optional<UserInfo> HttpServer::validate_user(const std::string& username) const {
    std::shared_lock lock(users_mutex_);

    const auto it = users_.find(username);
    if (it != users_.end()) {
        return it->second;
    }

    // If no users configured, allow all users (development mode)
    if (users_.empty()) {
        return UserInfo(std::string(username), {"user"});
    }

    return std::nullopt;  // User not found
}

std::optional<UserInfo> HttpServer::authenticate_api_key(const std::string& api_key) const {
    std::shared_lock lock(users_mutex_);
    const auto it = api_key_index_.find(api_key);
    if (it == api_key_index_.end()) {
        return std::nullopt;
    }
    const auto user_it = users_.find(it->second);
    if (user_it == users_.end()) {
        return std::nullopt;
    }
    return user_it->second;
}

void HttpServer::rebuild_api_key_index() {
    // Caller must hold unique_lock on users_mutex_
    api_key_index_.clear();
    api_key_index_.reserve(users_.size());
    for (const auto& [username, info] : users_) {
        if (!info.api_key.empty()) {
            api_key_index_[info.api_key] = username;
        }
    }
}

void HttpServer::update_users(std::unordered_map<std::string, UserInfo> new_users) {
    std::unique_lock lock(users_mutex_);
    users_ = std::move(new_users);
    rebuild_api_key_index();
    utils::log::info(std::format("Users reloaded: {} users", users_.size()));
}

void HttpServer::start() {
    httplib::Server svr;

    // POST /api/v1/query - Execute SELECT queries
    svr.Post("/api/v1/query", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            // Validate Content-Type
            std::string content_type = req.get_header_value("Content-Type");
            if (content_type.find(kJsonContentType) == std::string_view::npos) {
                res.status = httplib::StatusCode::BadRequest_400;
                res.set_content(R"({"success":false,"error":"Content-Type must be application/json"})", kJsonContentType);
                return;
            }

            // Basic JSON validation - check for opening/closing braces
            std::string_view body = req.body;
            if (body.empty() || body.find('{') == std::string_view::npos || body.find('}') == std::string_view::npos) {
                res.status = httplib::StatusCode::BadRequest_400;
                res.set_content(R"({"success":false,"error":"Invalid JSON: empty or malformed"})", kJsonContentType);
                return;
            }

            // Parse request fields as string_view (zero-copy until validation passes)
            auto sql_sv = parse_json_field(req.body, "sql");
            auto database_sv = parse_json_field(req.body, "database");

            // Validate required field: sql
            if (sql_sv.empty()) {
                res.status = httplib::StatusCode::BadRequest_400;
                res.set_content(R"({"success":false,"error":"Missing required field: sql"})", kJsonContentType);
                return;
            }

            // Validate SQL length
            const size_t max_sql = max_sql_length_.load();
            if (sql_sv.length() > max_sql) {
                res.status = httplib::StatusCode::BadRequest_400;
                res.set_content(
                    std::format(R"({{"success":false,"error":"SQL too long: max {} bytes"}})", max_sql),
                    "application/json");
                return;
            }

            // Authentication: Bearer token first, fallback to JSON body "user" field
            std::optional<UserInfo> user_info;
            std::string user;

            std::string auth_header = req.get_header_value("Authorization");
            constexpr std::string_view kBearerPrefix = "Bearer ";
            if (auth_header.size() > kBearerPrefix.size() &&
                std::string_view(auth_header).substr(0, kBearerPrefix.size()) == kBearerPrefix) {
                std::string api_key(std::string_view(auth_header).substr(kBearerPrefix.size()));
                user_info = authenticate_api_key(api_key);
                if (!user_info) {
                    res.status = httplib::StatusCode::Unauthorized_401;
                    res.set_content(R"({"success":false,"error":"Invalid API key"})", kJsonContentType);
                    return;
                }
                user = user_info->name;
            } else {
                // Fallback: user from JSON body
                auto user_sv = parse_json_field(req.body, "user");
                if (user_sv.empty()) {
                    res.status = httplib::StatusCode::BadRequest_400;
                    res.set_content(R"j({"success":false,"error":"Missing required field: user (or Authorization header)"})j", kJsonContentType);
                    return;
                }
                user = std::string(user_sv);
                user_info = validate_user(user);
                if (!user_info) {
                    res.status = httplib::StatusCode::Unauthorized_401;
                    res.set_content(
                        std::format(R"({{"success":false,"error":"Unknown user: {}"}})", user),
                        "application/json");
                    return;
                }
            }

            // Convert to owning strings only after validation passes
            std::string sql(sql_sv);
            std::string database = database_sv.empty()
                ? std::string("testdb")
                : std::string(database_sv);

            // Build proxy request
            ProxyRequest proxy_req;
            proxy_req.request_id = utils::generate_uuid();
            proxy_req.user = user;
            proxy_req.roles = user_info->roles;
            proxy_req.sql = sql;
            proxy_req.database = database;
            proxy_req.user_attributes = user_info->attributes;
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
                res.status = httplib::StatusCode::OK_200;
            } else {
                // O(1) lookup: ErrorCode enum index → HTTP status
                static constexpr httplib::StatusCode kErrorToHttp[] = {
                    httplib::StatusCode::OK_200,                  // NONE
                    httplib::StatusCode::BadRequest_400,           // PARSE_ERROR
                    httplib::StatusCode::Forbidden_403,            // ACCESS_DENIED
                    httplib::StatusCode::TooManyRequests_429,      // RATE_LIMITED
                    httplib::StatusCode::ServiceUnavailable_503,   // CIRCUIT_OPEN
                    httplib::StatusCode::BadGateway_502,           // DATABASE_ERROR
                    httplib::StatusCode::InternalServerError_500,  // INTERNAL_ERROR
                    httplib::StatusCode::BadRequest_400,           // INVALID_REQUEST
                    httplib::StatusCode::PayloadTooLarge_413,      // RESULT_TOO_LARGE
                };
                auto idx = static_cast<size_t>(response.error_code);
                res.status = (idx < std::size(kErrorToHttp))
                    ? kErrorToHttp[idx]
                    : httplib::StatusCode::InternalServerError_500;
            }

            res.set_content(json, kJsonContentType);

        } catch (const std::exception& e) {
            res.status = httplib::StatusCode::InternalServerError_500;
            res.set_content(
                std::format(R"({{"success":false,"error":"{}"}})", e.what()),
                "application/json");
        }
    });

    // GET /health - Health check
    svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        std::string health_json = R"({"status":"healthy","service":"sql-proxy"})";
        res.set_content(health_json, kJsonContentType);
    });

    // GET /metrics - Prometheus metrics endpoint
    svr.Get("/metrics", [this](const httplib::Request&, httplib::Response& res) {
        std::string output;

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

            output += std::format(
                "# HELP sql_proxy_requests_total Total number of requests processed\n"
                "# TYPE sql_proxy_requests_total counter\n"
                "sql_proxy_requests_total{{status=\"allowed\"}} {}\n"
                "sql_proxy_requests_total{{status=\"blocked\"}} {}\n\n"
                "# HELP sql_proxy_rate_limit_total Rate limit rejections by level\n"
                "# TYPE sql_proxy_rate_limit_total counter\n"
                "sql_proxy_rate_limit_total{{level=\"global\"}} {}\n"
                "sql_proxy_rate_limit_total{{level=\"user\"}} {}\n"
                "sql_proxy_rate_limit_total{{level=\"database\"}} {}\n"
                "sql_proxy_rate_limit_total{{level=\"user_database\"}} {}\n\n"
                "# HELP sql_proxy_rate_limit_checks_total Total rate limit checks performed\n"
                "# TYPE sql_proxy_rate_limit_checks_total counter\n"
                "sql_proxy_rate_limit_checks_total {}\n\n",
                total_allowed, total_rejects,
                rl_stats.global_rejects, rl_stats.user_rejects,
                rl_stats.database_rejects, rl_stats.user_database_rejects,
                rl_stats.total_checks);
        }

        // --- Audit emitter stats ---
        auto audit_emitter = pipeline_->get_audit_emitter();
        if (audit_emitter) {
            auto audit_stats = audit_emitter->get_stats();

            output += std::format(
                "# HELP sql_proxy_audit_emitted_total Audit records pushed to ring buffer\n"
                "# TYPE sql_proxy_audit_emitted_total counter\n"
                "sql_proxy_audit_emitted_total {}\n\n"
                "# HELP sql_proxy_audit_written_total Audit records written to file\n"
                "# TYPE sql_proxy_audit_written_total counter\n"
                "sql_proxy_audit_written_total {}\n\n"
                "# HELP sql_proxy_audit_dropped_total Audit records dropped due to buffer overflow\n"
                "# TYPE sql_proxy_audit_dropped_total counter\n"
                "sql_proxy_audit_dropped_total {}\n\n"
                "# HELP sql_proxy_audit_flushes_total Number of batch flushes performed\n"
                "# TYPE sql_proxy_audit_flushes_total counter\n"
                "sql_proxy_audit_flushes_total {}\n\n",
                audit_stats.total_emitted, audit_stats.total_written,
                audit_stats.overflow_dropped, audit_stats.flush_count);
        }

        // --- Build info ---
        output += "# HELP sql_proxy_info Build information\n"
                  "# TYPE sql_proxy_info gauge\n"
                  "sql_proxy_info{version=\"1.0.0\"} 1\n";

        res.set_content(output, "text/plain; version=0.0.4; charset=utf-8");
    });

    // POST /policies/reload - Hot reload policies from config file
    svr.Post("/policies/reload", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            // Validate admin token if configured
            if (!admin_token_.empty()) {
                auto auth = req.get_header_value("Authorization");
                constexpr std::string_view kBearerPrefix = "Bearer ";
                if (auth.size() <= kBearerPrefix.size() ||
                    std::string_view(auth).substr(0, kBearerPrefix.size()) != kBearerPrefix ||
                    std::string_view(auth).substr(kBearerPrefix.size()) != admin_token_) {
                    res.status = httplib::StatusCode::Unauthorized_401;
                    res.set_content(R"({"success":false,"error":"Unauthorized: invalid or missing admin token"})", kJsonContentType);
                    return;
                }
            }

            // Load policies from config file
            std::string config_path = "config/proxy.toml";
            auto load_result = PolicyLoader::load_from_file(config_path);

            if (!load_result.success) {
                res.status = httplib::StatusCode::BadRequest_400;
                res.set_content(
                    std::format(R"({{"success":false,"error":"{}"}})", load_result.error_message),
                    "application/json");
                return;
            }

            // Hot reload policies via RCU (zero downtime)
            pipeline_->get_policy_engine()->reload_policies(load_result.policies);

            // Success response
            res.status = httplib::StatusCode::OK_200;
            res.set_content(
                std::format(R"({{"success":true,"policies_loaded":{}}})", load_result.policies.size()),
                "application/json");

            utils::log::info(std::format("Policies reloaded: {} policies loaded", load_result.policies.size()));

        } catch (const std::exception& e) {
            res.status = httplib::StatusCode::InternalServerError_500;
            res.set_content(
                std::format(R"({{"success":false,"error":"{}"}})", e.what()),
                "application/json");
        }
    });

    utils::log::info(std::format("Starting SQL Proxy Server on {}:{}", host_, port_));
    utils::log::info("Endpoints: POST /api/v1/query, GET /health, GET /metrics, POST /policies/reload");

    if (!svr.listen(host_.c_str(), port_)) {
        throw std::runtime_error("Failed to start HTTP server");
    }
}

void HttpServer::stop() {
    utils::log::info("Server stopped");
}

} // namespace sqlproxy
