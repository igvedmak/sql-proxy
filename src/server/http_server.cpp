#include "server/http_server.hpp"
#include "server/http_constants.hpp"
#include "server/openapi_handler.hpp"
#include "server/request_priority.hpp"
#include "server/adaptive_rate_controller.hpp"
#include "server/rate_limiter.hpp"
#include "server/waitable_rate_limiter.hpp"
#include "server/shutdown_coordinator.hpp"
#include "server/response_compressor.hpp"
#include "cache/result_cache.hpp"
#include "server/graphql_handler.hpp"
#include "server/dashboard_handler.hpp"
#include "audit/audit_emitter.hpp"
#include "config/config_loader.hpp"
#include "core/slow_query_tracker.hpp"
#include "core/utils.hpp"
#include "executor/circuit_breaker.hpp"
#include "db/iconnection_pool.hpp"
#include "parser/parse_cache.hpp"
#include "policy/policy_loader.hpp"
#include "security/brute_force_protector.hpp"
#include "security/compliance_reporter.hpp"
#include "security/ip_allowlist.hpp"
#include "security/lineage_tracker.hpp"
#include "schema/schema_manager.hpp"
#include "schema/schema_drift_detector.hpp"
#include "core/query_cost_estimator.hpp"

// cpp-httplib is header-only — suppress its internal deprecation warnings
#define CPPHTTPLIB_OPENSSL_SUPPORT
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include "../third_party/cpp-httplib/httplib.h"
#pragma GCC diagnostic pop

#include <format>
#include <string_view>

namespace sqlproxy {

// ============================================================================
// Anonymous namespace helpers
// ============================================================================

namespace {

std::string_view parse_json_field(std::string_view json, std::string_view field) {
    char quote_char = '"';
    size_t pos = 0;
    while ((pos = json.find(quote_char, pos)) != std::string_view::npos) {
        if (pos + field.size() + 1 < json.size() &&
            json.substr(pos + 1, field.size()) == field &&
            json[pos + field.size() + 1] == quote_char) {
            pos += field.size() + 2;
            pos = json.find(quote_char, pos);
            if (pos == std::string_view::npos) return "";
            const size_t end = json.find(quote_char, pos + 1);
            if (end == std::string_view::npos) return "";
            return json.substr(pos + 1, end - pos - 1);
        }
        ++pos;
    }
    return "";
}

std::atomic<uint64_t> s_ip_blocks{0};
std::atomic<uint64_t> s_auth_rejects{0};
std::atomic<uint64_t> s_brute_force_blocks{0};

bool require_admin(std::string_view admin_token,
                   const httplib::Request& req, httplib::Response& res) {
    if (admin_token.empty()) return true;
    const auto auth = req.get_header_value(http::kAuthorizationHeader);
    if (auth.size() <= http::kBearerPrefix.size() ||
        std::string_view(auth).substr(0, http::kBearerPrefix.size()) != http::kBearerPrefix ||
        std::string_view(auth).substr(http::kBearerPrefix.size()) != admin_token) {
        res.status = httplib::StatusCode::Unauthorized_401;
        res.set_content(R"({"success":false,"error":"Unauthorized"})", http::kJsonContentType);
        return false;
    }
    return true;
}

std::string build_json_response(const ProxyResponse& response) {
    std::string result_str;
    // Pre-allocate based on result size to avoid repeated reallocations.
    // Estimate: ~100 bytes overhead + ~50 bytes per column + ~100 bytes per cell.
    if (response.result.has_value()) {
        const auto& r = *response.result;
        const size_t cell_count = r.rows.size() * r.column_names.size();
        result_str.reserve(256 + r.column_names.size() * 50 + cell_count * 100);
    } else {
        result_str.reserve(256);
    }
    result_str += std::format("{{\"success\":{},\"audit_id\":\"{}\",",
                              utils::booltostr(response.success),
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

        if (!response.masked_columns.empty()) {
            result_str += "\"masked_columns\":[";
            for (size_t i = 0; i < response.masked_columns.size(); ++i) {
                if (i > 0) result_str += ",";
                result_str += std::format("\"{}\"", response.masked_columns[i]);
            }
            result_str += "],";
        }

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

// RAII guard for shutdown coordinator
struct ShutdownGuard {
    ShutdownCoordinator* sc;
    ~ShutdownGuard() { if (sc) sc->leave_request(); }
};

} // anonymous namespace

// ============================================================================
// Constructor
// ============================================================================

HttpServer::HttpServer(
    std::shared_ptr<Pipeline> pipeline,
    std::string host,
    int port,
    std::unordered_map<std::string, UserInfo> users,
    std::string admin_token,
    size_t max_sql_length,
    std::shared_ptr<ComplianceReporter> compliance_reporter,
    std::shared_ptr<LineageTracker> lineage_tracker,
    std::shared_ptr<SchemaManager> schema_manager,
    std::shared_ptr<GraphQLHandler> graphql_handler,
    std::shared_ptr<DashboardHandler> dashboard_handler,
    TlsConfig tls_config,
    ResponseCompressor::Config compressor_config,
    RouteConfig routes,
    FeatureFlags features,
    size_t thread_pool_size)
    : pipeline_(std::move(pipeline)),
      host_(std::move(host)),
      port_(port),
      admin_token_(std::move(admin_token)),
      tls_config_(std::move(tls_config)),
      routes_(std::move(routes)),
      features_(features),
      thread_pool_size_(thread_pool_size),
      users_(std::move(users)),
      max_sql_length_(max_sql_length),
      compliance_reporter_(std::move(compliance_reporter)),
      lineage_tracker_(std::move(lineage_tracker)),
      schema_manager_(std::move(schema_manager)),
      graphql_handler_(std::move(graphql_handler)),
      dashboard_handler_(std::move(dashboard_handler)),
      compressor_(compressor_config) {
    rebuild_api_key_index();
}

// ============================================================================
// Authentication
// ============================================================================

std::optional<UserInfo> HttpServer::validate_user(const std::string& username) const {
    std::shared_lock lock(users_mutex_);
    const auto it = users_.find(username);
    if (it != users_.end()) return it->second;
    if (users_.empty()) return UserInfo(std::string(username), {"user"});
    return std::nullopt;
}

std::optional<UserInfo> HttpServer::authenticate_api_key(const std::string& api_key) const {
    std::shared_lock lock(users_mutex_);
    const auto it = api_key_index_.find(api_key);
    if (it == api_key_index_.end()) return std::nullopt;
    const auto user_it = users_.find(it->second);
    if (user_it == users_.end()) return std::nullopt;
    return user_it->second;
}

void HttpServer::rebuild_api_key_index() {
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

// ============================================================================
// start() — creates server, registers routes, listens
// ============================================================================

void HttpServer::start() {
    std::unique_ptr<httplib::Server> svr_ptr;
    if (tls_config_.enabled && !tls_config_.cert_file.empty() && !tls_config_.key_file.empty()) {
        const char* ca_cert_path = (tls_config_.require_client_cert && !tls_config_.ca_file.empty())
            ? tls_config_.ca_file.c_str() : nullptr;
        auto ssl_svr = std::make_unique<httplib::SSLServer>(
            tls_config_.cert_file.c_str(), tls_config_.key_file.c_str(), ca_cert_path);
        utils::log::info(std::format("TLS enabled: cert={}, key={}, mTLS={}",
            tls_config_.cert_file, tls_config_.key_file,
            tls_config_.require_client_cert ? "required" : "off"));
        svr_ptr = std::move(ssl_svr);
    } else {
        svr_ptr = std::make_unique<httplib::Server>();
    }
    auto& svr = *svr_ptr;

    // Configure thread pool size for high throughput
    const size_t pool_size = thread_pool_size_;
    svr.new_task_queue = [pool_size] {
        return new httplib::ThreadPool(pool_size);
    };

    register_core_routes(svr);
    register_admin_routes(svr);
    register_compliance_routes(svr);
    register_schema_routes(svr);
    register_optional_routes(svr);

    utils::log::info(std::format("Starting SQL Proxy Server on {}:{} ({}, {} threads)",
        host_, port_, tls_config_.enabled ? "HTTPS" : "HTTP", thread_pool_size_));

    if (!svr.listen(host_.c_str(), port_)) {
        throw std::runtime_error("Failed to start HTTP server");
    }
}

void HttpServer::stop() {
    utils::log::info("Server stopped");
}

HttpServer::HttpStats HttpServer::get_http_stats() {
    return {
        s_auth_rejects.load(std::memory_order_relaxed),
        s_brute_force_blocks.load(std::memory_order_relaxed),
        s_ip_blocks.load(std::memory_order_relaxed)
    };
}

// ============================================================================
// Route registration groups
// ============================================================================

void HttpServer::register_core_routes(httplib::Server& svr) {
    svr.Post(routes_.query, [this](const httplib::Request& req, httplib::Response& res) {
        handle_query(req, res);
    });
    svr.Get(routes_.health, [this](const httplib::Request& req, httplib::Response& res) {
        handle_health(req, res);
    });
    if (features_.openapi) {
        svr.Get(routes_.openapi_spec, [](const httplib::Request&, httplib::Response& res) {
            res.set_content(OpenAPIHandler::get_spec_json(), "application/json");
        });
    }
    if (features_.swagger_ui) {
        svr.Get(routes_.swagger_ui, [](const httplib::Request&, httplib::Response& res) {
            res.set_content(OpenAPIHandler::get_swagger_html(), "text/html");
        });
    }
    if (features_.dry_run) {
        svr.Post(routes_.dry_run, [this](const httplib::Request& req, httplib::Response& res) {
            handle_dry_run(req, res);
        });
    }
    if (features_.metrics) {
        svr.Get(routes_.metrics, [this](const httplib::Request& req, httplib::Response& res) {
            handle_metrics(req, res);
        });
    }
}

void HttpServer::register_admin_routes(httplib::Server& svr) {
    svr.Post(routes_.policies_reload, [this](const httplib::Request& req, httplib::Response& res) {
        handle_policies_reload(req, res);
    });
    svr.Post(routes_.config_validate, [this](const httplib::Request& req, httplib::Response& res) {
        handle_config_validate(req, res);
    });
    svr.Get(routes_.circuit_breakers, [this](const httplib::Request& req, httplib::Response& res) {
        handle_circuit_breakers(req, res);
    });
    if (features_.slow_query) {
        svr.Get(routes_.slow_queries, [this](const httplib::Request& req, httplib::Response& res) {
            handle_slow_queries(req, res);
        });
    }
}

void HttpServer::register_compliance_routes(httplib::Server& svr) {
    if (features_.classification) {
        svr.Get(routes_.pii_report, [this](const httplib::Request& req, httplib::Response& res) {
            handle_pii_report(req, res);
        });
    }
    if (features_.injection_detection) {
        svr.Get(routes_.security_summary, [this](const httplib::Request& req, httplib::Response& res) {
            handle_security_summary(req, res);
        });
    }
    if (features_.lineage_tracking) {
        svr.Get(routes_.lineage, [this](const httplib::Request& req, httplib::Response& res) {
            handle_lineage(req, res);
        });
    }
    svr.Get(routes_.data_subject_access, [this](const httplib::Request& req, httplib::Response& res) {
        handle_data_subject_access(req, res);
    });
}

void HttpServer::register_schema_routes(httplib::Server& svr) {
    if (schema_manager_) {
        svr.Get(routes_.schema_history, [this](const httplib::Request& req, httplib::Response& res) {
            handle_schema_history(req, res);
        });
        svr.Get(routes_.schema_pending, [this](const httplib::Request& req, httplib::Response& res) {
            handle_schema_pending(req, res);
        });
        svr.Post(routes_.schema_approve, [this](const httplib::Request& req, httplib::Response& res) {
            handle_schema_approve(req, res);
        });
        svr.Post(routes_.schema_reject, [this](const httplib::Request& req, httplib::Response& res) {
            handle_schema_reject(req, res);
        });
    }
    if (features_.schema_drift) {
        svr.Get(routes_.schema_drift, [this](const httplib::Request& req, httplib::Response& res) {
            handle_schema_drift(req, res);
        });
    }
}

void HttpServer::register_optional_routes(httplib::Server& svr) {
    if (graphql_handler_) {
        svr.Post(routes_.graphql, [this](const httplib::Request& req, httplib::Response& res) {
            handle_graphql(req, res);
        });
    }
    if (features_.dashboard && dashboard_handler_) {
        dashboard_handler_->register_routes(svr, admin_token_);
    }
}

// ============================================================================
// Handler: POST /api/v1/query
// ============================================================================

void HttpServer::handle_query(const httplib::Request& req, httplib::Response& res) {
    if (shutdown_coordinator_ && !shutdown_coordinator_->try_enter_request()) {
        res.status = httplib::StatusCode::ServiceUnavailable_503;
        res.set_content(R"({"success":false,"error":"Server shutting down"})", http::kJsonContentType);
        return;
    }
    ShutdownGuard shutdown_guard{shutdown_coordinator_.get()};

    try {
        // Validate Content-Type
        const std::string content_type = req.get_header_value("Content-Type");
        if (!content_type.contains(http::kJsonContentType)) {
            res.status = httplib::StatusCode::BadRequest_400;
            res.set_content(R"({"success":false,"error":"Content-Type must be application/json"})", http::kJsonContentType);
            return;
        }

        // Basic JSON validation
        std::string_view body = req.body;
        if (body.empty() || !body.contains('{') || !body.contains('}')) {
            res.status = httplib::StatusCode::BadRequest_400;
            res.set_content(R"({"success":false,"error":"Invalid JSON: empty or malformed"})", http::kJsonContentType);
            return;
        }

        const auto sql_sv = parse_json_field(req.body, "sql");
        const auto database_sv = parse_json_field(req.body, "database");

        if (sql_sv.empty()) {
            res.status = httplib::StatusCode::BadRequest_400;
            res.set_content(R"({"success":false,"error":"Missing required field: sql"})", http::kJsonContentType);
            return;
        }

        const size_t max_sql = max_sql_length_.load();
        if (sql_sv.length() > max_sql) {
            res.status = httplib::StatusCode::BadRequest_400;
            res.set_content(
                std::format(R"({{"success":false,"error":"SQL too long: max {} bytes"}})", max_sql),
                http::kJsonContentType);
            return;
        }

        // Extract source IP
        std::string source_ip = req.get_header_value("X-Forwarded-For");
        if (source_ip.empty()) source_ip = req.remote_addr;
        if (const auto comma = source_ip.find(','); comma != std::string::npos) {
            source_ip = source_ip.substr(0, comma);
        }

        // Authentication: Bearer token first, fallback to JSON body "user" field
        std::optional<UserInfo> user_info;
        std::string user;

        const std::string auth_header = req.get_header_value(http::kAuthorizationHeader);
        if (auth_header.size() > http::kBearerPrefix.size() &&
            std::string_view(auth_header).substr(0, http::kBearerPrefix.size()) == http::kBearerPrefix) {
            const std::string api_key(std::string_view(auth_header).substr(http::kBearerPrefix.size()));

            if (brute_force_protector_) {
                const auto block = brute_force_protector_->is_blocked(source_ip, "");
                if (block.blocked) {
                    s_brute_force_blocks.fetch_add(1, std::memory_order_relaxed);
                    res.status = httplib::StatusCode::TooManyRequests_429;
                    res.set_header("Retry-After", std::format("{}", block.retry_after_seconds));
                    res.set_content(std::format(R"({{"success":false,"error":"{}"}})", block.reason), http::kJsonContentType);
                    return;
                }
            }

            user_info = authenticate_api_key(api_key);
            if (!user_info) {
                s_auth_rejects.fetch_add(1, std::memory_order_relaxed);
                if (brute_force_protector_) brute_force_protector_->record_failure(source_ip, "");
                res.status = httplib::StatusCode::Unauthorized_401;
                res.set_content(R"({"success":false,"error":"Invalid API key"})", http::kJsonContentType);
                return;
            }
            if (brute_force_protector_) brute_force_protector_->record_success(source_ip, user_info->name);
            user = user_info->name;
        } else {
            const auto user_sv = parse_json_field(req.body, "user");
            if (user_sv.empty()) {
                res.status = httplib::StatusCode::BadRequest_400;
                res.set_content(R"j({"success":false,"error":"Missing required field: user (or Authorization header)"})j", http::kJsonContentType);
                return;
            }
            user = std::string(user_sv);

            if (brute_force_protector_) {
                const auto block = brute_force_protector_->is_blocked(source_ip, user);
                if (block.blocked) {
                    s_brute_force_blocks.fetch_add(1, std::memory_order_relaxed);
                    res.status = httplib::StatusCode::TooManyRequests_429;
                    res.set_header("Retry-After", std::format("{}", block.retry_after_seconds));
                    res.set_content(std::format(R"({{"success":false,"error":"{}"}})", block.reason), http::kJsonContentType);
                    return;
                }
            }

            user_info = validate_user(user);
            if (!user_info) {
                s_auth_rejects.fetch_add(1, std::memory_order_relaxed);
                if (brute_force_protector_) brute_force_protector_->record_failure(source_ip, user);
                res.status = httplib::StatusCode::Unauthorized_401;
                res.set_content(
                    std::format(R"({{"success":false,"error":"Unknown user: {}"}})", user),
                    http::kJsonContentType);
                return;
            }
            if (brute_force_protector_) brute_force_protector_->record_success(source_ip, user);
        }

        // IP allowlist check
        if (user_info && !user_info->allowed_ips.empty()) {
            if (!IpAllowlist::is_allowed(source_ip, user_info->allowed_ips)) {
                s_ip_blocks.fetch_add(1, std::memory_order_relaxed);
                res.status = httplib::StatusCode::Forbidden_403;
                res.set_content(R"({"success":false,"error":"IP address not allowed for this user"})", http::kJsonContentType);
                return;
            }
        }

        // Build proxy request
        const std::string sql(sql_sv);
        std::string database;
        if (!database_sv.empty()) {
            database = std::string(database_sv);
        } else if (user_info && !user_info->default_database.empty()) {
            database = user_info->default_database;
        } else {
            database = "testdb";
        }

        ProxyRequest proxy_req;
        proxy_req.user = user;
        proxy_req.roles = user_info->roles;
        proxy_req.sql = sql;
        proxy_req.database = database;
        proxy_req.user_attributes = user_info->attributes;
        proxy_req.source_ip = req.get_header_value("X-Forwarded-For");
        if (proxy_req.source_ip.empty()) proxy_req.source_ip = req.remote_addr;
        proxy_req.traceparent = req.get_header_value("traceparent");
        proxy_req.tracestate = req.get_header_value("tracestate");

        const auto priority_sv = parse_json_field(req.body, "priority");
        if (!priority_sv.empty()) {
            proxy_req.priority = parse_priority(priority_sv);
        }

        // Execute through pipeline
        const auto response = pipeline_->execute(proxy_req);

        if (!response.traceparent.empty()) {
            res.set_header("traceparent", response.traceparent);
        }

        const std::string json = build_json_response(response);

        // Map error code to HTTP status
        if (response.success) {
            res.status = httplib::StatusCode::OK_200;
        } else {
            static constexpr httplib::StatusCode kErrorToHttp[] = {
                httplib::StatusCode::OK_200,                   // NONE
                httplib::StatusCode::BadRequest_400,           // PARSE_ERROR
                httplib::StatusCode::Forbidden_403,            // ACCESS_DENIED
                httplib::StatusCode::TooManyRequests_429,      // RATE_LIMITED
                httplib::StatusCode::ServiceUnavailable_503,   // CIRCUIT_OPEN
                httplib::StatusCode::BadGateway_502,           // DATABASE_ERROR
                httplib::StatusCode::InternalServerError_500,  // INTERNAL_ERROR
                httplib::StatusCode::BadRequest_400,           // INVALID_REQUEST
                httplib::StatusCode::PayloadTooLarge_413,      // RESULT_TOO_LARGE
                httplib::StatusCode::Forbidden_403,            // SQLI_BLOCKED
                httplib::StatusCode::RequestTimeout_408,       // QUERY_TIMEOUT
                httplib::StatusCode::Forbidden_403,            // QUERY_TOO_EXPENSIVE
            };
            const size_t idx = static_cast<size_t>(response.error_code);
            res.status = (idx < std::size(kErrorToHttp))
                ? kErrorToHttp[idx]
                : httplib::StatusCode::InternalServerError_500;
        }

        // Rate limit headers
        res.set_header("X-RateLimit-Remaining",
            std::format("{}", response.rate_limit_info.tokens_remaining));
        if (!response.rate_limit_info.allowed) {
            const auto retry_seconds = response.rate_limit_info.retry_after.count() / 1000;
            res.set_header("Retry-After", std::format("{}", (retry_seconds < 1) ? 1 : retry_seconds));
        }

        // Gzip compression
        if (compressor_.should_compress(json.size())) {
            const std::string accept_enc = req.get_header_value("Accept-Encoding");
            if (accept_enc.contains("gzip")) {
                if (auto compressed = compressor_.try_compress(json)) {
                    res.set_header("Content-Encoding", "gzip");
                    res.set_content(std::move(*compressed), http::kJsonContentType);
                    return;
                }
            }
        }

        res.set_content(json, http::kJsonContentType);

    } catch (const std::exception& e) {
        res.status = httplib::StatusCode::InternalServerError_500;
        res.set_content(
            std::format(R"({{"success":false,"error":"{}"}})", e.what()),
            http::kJsonContentType);
    }
}

// ============================================================================
// Handler: POST /api/v1/query/dry-run
// ============================================================================

void HttpServer::handle_dry_run(const httplib::Request& req, httplib::Response& res) {
    if (shutdown_coordinator_ && !shutdown_coordinator_->try_enter_request()) {
        res.status = httplib::StatusCode::ServiceUnavailable_503;
        res.set_content(R"({"success":false,"error":"Server shutting down"})", http::kJsonContentType);
        return;
    }
    ShutdownGuard shutdown_guard{shutdown_coordinator_.get()};

    try {
        const auto sql_sv = parse_json_field(req.body, "sql");
        const auto user_sv = parse_json_field(req.body, "user");
        const auto db_sv = parse_json_field(req.body, "database");

        if (sql_sv.empty()) {
            res.status = httplib::StatusCode::BadRequest_400;
            res.set_content(R"({"success":false,"error":"Missing field: sql"})", http::kJsonContentType);
            return;
        }

        const std::string user = user_sv.empty() ? "anonymous" : std::string(user_sv);
        const std::string database = db_sv.empty() ? "testdb" : std::string(db_sv);

        const auto user_info = validate_user(user);
        std::vector<std::string> roles;
        if (user_info) roles = user_info->roles;

        ProxyRequest proxy_req;
        proxy_req.user = user;
        proxy_req.roles = roles;
        proxy_req.sql = std::string(sql_sv);
        proxy_req.database = database;
        proxy_req.dry_run = true;

        const auto response = pipeline_->execute(proxy_req);

        const std::string json = std::format(
            R"({{"dry_run":true,"would_succeed":{},"policy_decision":"{}","matched_policy":"{}","shadow_blocked":{}{}}})",
            utils::booltostr(response.success),
            decision_to_string(response.policy_decision),
            response.matched_policy,
            utils::booltostr(response.shadow_blocked),
            response.shadow_blocked
                ? std::format(",\"shadow_policy\":\"{}\"", response.shadow_policy)
                : "");

        res.set_content(json, http::kJsonContentType);
    } catch (const std::exception& e) {
        res.status = httplib::StatusCode::InternalServerError_500;
        res.set_content(
            std::format(R"({{"success":false,"error":"{}"}})", e.what()),
            http::kJsonContentType);
    }
}

// ============================================================================
// Handler: GET /health
// ============================================================================

void HttpServer::handle_health(const httplib::Request& req, httplib::Response& res) {
    const std::string level = req.get_param_value("level");

    if (level.empty() || level == "shallow") {
        res.set_content(R"({"status":"healthy","service":"sql-proxy"})", http::kJsonContentType);
        return;
    }

    bool all_ok = true;
    std::string checks;

    const auto cb = pipeline_->get_circuit_breaker();
    if (cb) {
        const auto state = cb->get_state();
        const bool cb_ok = (state == CircuitState::CLOSED);
        if (!cb_ok) all_ok = false;
        const char* state_str = (state == CircuitState::CLOSED) ? "closed" :
                                (state == CircuitState::OPEN) ? "open" : "half_open";
        checks += std::format(R"("circuit_breaker":"{}")", cb_ok ? "ok" : state_str);
    } else {
        checks += R"("circuit_breaker":"ok")";
    }

    const auto pool = pipeline_->get_connection_pool();
    if (pool) {
        const auto ps = pool->get_stats();
        const bool pool_ok = (ps.idle_connections > 0 || ps.active_connections < ps.total_connections);
        if (!pool_ok) all_ok = false;
        checks += std::format(R"(,"connection_pool":"{}")", pool_ok ? "ok" : "exhausted");
    } else {
        checks += R"(,"connection_pool":"ok")";
    }

    const auto audit = pipeline_->get_audit_emitter();
    if (audit) {
        const auto as = audit->get_stats();
        const bool audit_ok = (as.overflow_dropped == 0);
        if (!audit_ok) all_ok = false;
        checks += std::format(R"(,"audit":"{}")", audit_ok ? "ok" : "dropping");
    } else {
        checks += R"(,"audit":"ok")";
    }

    if (level == "readiness") {
        const auto rl = pipeline_->get_rate_limiter();
        const auto* hierarchical_rl = dynamic_cast<HierarchicalRateLimiter*>(rl.get());
        if (hierarchical_rl) {
            const auto rs = hierarchical_rl->get_stats();
            const uint64_t total_rejects = rs.global_rejects + rs.user_rejects +
                rs.database_rejects + rs.user_database_rejects;
            const bool rl_ok = (rs.total_checks == 0 || total_rejects * 2 < rs.total_checks);
            if (!rl_ok) all_ok = false;
            checks += std::format(R"(,"rate_limiter":"{}")", rl_ok ? "ok" : "overloaded");
        } else {
            checks += R"(,"rate_limiter":"ok")";
        }
    }

    const auto status = all_ok ? "healthy" : "unhealthy";
    const auto body = std::format(
        R"({{"status":"{}","service":"sql-proxy","checks":{{{}}}}})", status, checks);

    res.status = all_ok ? httplib::StatusCode::OK_200 : httplib::StatusCode::ServiceUnavailable_503;
    res.set_content(body, http::kJsonContentType);
}

// ============================================================================
// Handler: GET /metrics
// ============================================================================

void HttpServer::handle_metrics(const httplib::Request&, httplib::Response& res) {
    res.set_content(build_metrics_output(), "text/plain; version=0.0.4; charset=utf-8");
}

std::string HttpServer::build_metrics_output() {
    std::string output;

    const auto ps = pipeline_->get_stats();
    const uint64_t allowed = (ps.total_requests > ps.requests_blocked)
                     ? (ps.total_requests - ps.requests_blocked) : 0;
    output += std::format(
        "# HELP sql_proxy_requests_total Total number of requests processed\n"
        "# TYPE sql_proxy_requests_total counter\n"
        "sql_proxy_requests_total{{status=\"allowed\"}} {}\n"
        "sql_proxy_requests_total{{status=\"blocked\"}} {}\n\n",
        allowed, ps.requests_blocked);

    const auto rate_limiter = pipeline_->get_rate_limiter();
    const auto* hierarchical_rl = dynamic_cast<HierarchicalRateLimiter*>(rate_limiter.get());
    if (hierarchical_rl) {
        const auto rl_stats = hierarchical_rl->get_stats();
        output += std::format(
            "# HELP sql_proxy_rate_limit_total Rate limit rejections by level\n"
            "# TYPE sql_proxy_rate_limit_total counter\n"
            "sql_proxy_rate_limit_total{{level=\"global\"}} {}\n"
            "sql_proxy_rate_limit_total{{level=\"user\"}} {}\n"
            "sql_proxy_rate_limit_total{{level=\"database\"}} {}\n"
            "sql_proxy_rate_limit_total{{level=\"user_database\"}} {}\n\n"
            "# HELP sql_proxy_rate_limit_checks_total Total rate limit checks performed\n"
            "# TYPE sql_proxy_rate_limit_checks_total counter\n"
            "sql_proxy_rate_limit_checks_total {}\n\n",
            rl_stats.global_rejects, rl_stats.user_rejects,
            rl_stats.database_rejects, rl_stats.user_database_rejects,
            rl_stats.total_checks);
    }

    const auto* waitable_rl = dynamic_cast<WaitableRateLimiter*>(rate_limiter.get());
    if (waitable_rl) {
        output += std::format(
            "# HELP sql_proxy_queue_depth Current requests waiting in queue\n"
            "# TYPE sql_proxy_queue_depth gauge\n"
            "sql_proxy_queue_depth {}\n\n"
            "# HELP sql_proxy_queue_total Total requests that entered queue\n"
            "# TYPE sql_proxy_queue_total counter\n"
            "sql_proxy_queue_total {}\n\n"
            "# HELP sql_proxy_queue_timeouts_total Queue timeout count\n"
            "# TYPE sql_proxy_queue_timeouts_total counter\n"
            "sql_proxy_queue_timeouts_total {}\n\n",
            waitable_rl->current_queue_depth(),
            waitable_rl->queued_total(),
            waitable_rl->queue_timeouts());
    }

    const auto audit_emitter = pipeline_->get_audit_emitter();
    if (audit_emitter) {
        const auto audit_stats = audit_emitter->get_stats();
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

    const auto result_cache = pipeline_->get_result_cache();
    if (result_cache && result_cache->is_enabled()) {
        const auto cache_stats = result_cache->get_stats();
        output += std::format(
            "# HELP sql_proxy_cache_hits_total Cache hit count\n"
            "# TYPE sql_proxy_cache_hits_total counter\n"
            "sql_proxy_cache_hits_total {}\n\n"
            "# HELP sql_proxy_cache_misses_total Cache miss count\n"
            "# TYPE sql_proxy_cache_misses_total counter\n"
            "sql_proxy_cache_misses_total {}\n\n"
            "# HELP sql_proxy_cache_entries Current cache entries\n"
            "# TYPE sql_proxy_cache_entries gauge\n"
            "sql_proxy_cache_entries {}\n\n"
            "# HELP sql_proxy_cache_evictions_total Cache eviction count\n"
            "# TYPE sql_proxy_cache_evictions_total counter\n"
            "sql_proxy_cache_evictions_total {}\n\n",
            cache_stats.hits, cache_stats.misses,
            cache_stats.current_entries, cache_stats.evictions);
    }

    const auto slow_tracker = pipeline_->get_slow_query_tracker();
    if (slow_tracker && slow_tracker->is_enabled()) {
        output += std::format(
            "# HELP sql_proxy_slow_queries_total Total slow queries detected\n"
            "# TYPE sql_proxy_slow_queries_total counter\n"
            "sql_proxy_slow_queries_total {}\n\n",
            slow_tracker->total_slow_queries());
    }

    const auto cb = pipeline_->get_circuit_breaker();
    if (cb) {
        const auto events = cb->get_recent_events();
        uint64_t to_open = 0, to_half_open = 0, to_closed = 0;
        for (const auto& e : events) {
            if (e.to == CircuitState::OPEN) ++to_open;
            else if (e.to == CircuitState::HALF_OPEN) ++to_half_open;
            else if (e.to == CircuitState::CLOSED) ++to_closed;
        }
        output += std::format(
            "# HELP sql_proxy_circuit_breaker_transitions_total Circuit breaker state transitions\n"
            "# TYPE sql_proxy_circuit_breaker_transitions_total counter\n"
            "sql_proxy_circuit_breaker_transitions_total{{to=\"open\"}} {}\n"
            "sql_proxy_circuit_breaker_transitions_total{{to=\"half_open\"}} {}\n"
            "sql_proxy_circuit_breaker_transitions_total{{to=\"closed\"}} {}\n\n",
            to_open, to_half_open, to_closed);
    }

    if (hierarchical_rl) {
        const auto rl_stats = hierarchical_rl->get_stats();
        output += std::format(
            "# HELP sql_proxy_rate_limiter_buckets_active Active rate limiter buckets\n"
            "# TYPE sql_proxy_rate_limiter_buckets_active gauge\n"
            "sql_proxy_rate_limiter_buckets_active {}\n\n"
            "# HELP sql_proxy_rate_limiter_buckets_evicted_total Evicted idle buckets\n"
            "# TYPE sql_proxy_rate_limiter_buckets_evicted_total counter\n"
            "sql_proxy_rate_limiter_buckets_evicted_total {}\n\n",
            rl_stats.user_bucket_count + rl_stats.db_bucket_count + rl_stats.user_db_bucket_count,
            rl_stats.buckets_evicted);
    }

    const auto pool = pipeline_->get_connection_pool();
    if (pool) {
        const auto pool_stats = pool->get_stats();
        output += std::format(
            "# HELP sql_proxy_pool_connections_recycled_total Connections recycled due to max lifetime\n"
            "# TYPE sql_proxy_pool_connections_recycled_total counter\n"
            "sql_proxy_pool_connections_recycled_total {}\n\n",
            pool_stats.connections_recycled);

        const auto& b = pool_stats.acquire_time_buckets;
        const uint64_t c0 = b[0];
        const uint64_t c1 = c0 + b[1];
        const uint64_t c2 = c1 + b[2];
        const uint64_t c3 = c2 + b[3];
        const uint64_t c4 = c3 + b[4];
        const uint64_t c5 = c4 + b[5];
        const double sum_sec = static_cast<double>(pool_stats.acquire_time_sum_us) / 1e6;
        output += std::format(
            "# HELP sql_proxy_pool_acquire_duration_seconds Connection pool acquire time\n"
            "# TYPE sql_proxy_pool_acquire_duration_seconds histogram\n"
            "sql_proxy_pool_acquire_duration_seconds_bucket{{le=\"0.0001\"}} {}\n"
            "sql_proxy_pool_acquire_duration_seconds_bucket{{le=\"0.0005\"}} {}\n"
            "sql_proxy_pool_acquire_duration_seconds_bucket{{le=\"0.001\"}} {}\n"
            "sql_proxy_pool_acquire_duration_seconds_bucket{{le=\"0.005\"}} {}\n"
            "sql_proxy_pool_acquire_duration_seconds_bucket{{le=\"0.05\"}} {}\n"
            "sql_proxy_pool_acquire_duration_seconds_bucket{{le=\"+Inf\"}} {}\n"
            "sql_proxy_pool_acquire_duration_seconds_sum {:.6f}\n"
            "sql_proxy_pool_acquire_duration_seconds_count {}\n\n",
            c0, c1, c2, c3, c4, c5, sum_sec, pool_stats.acquire_time_count);
    }

    const auto parse_cache = pipeline_->get_parse_cache();
    if (parse_cache) {
        const auto pc_stats = parse_cache->get_stats();
        output += std::format(
            "# HELP sql_proxy_cache_ddl_invalidations_total Cache entries invalidated by DDL\n"
            "# TYPE sql_proxy_cache_ddl_invalidations_total counter\n"
            "sql_proxy_cache_ddl_invalidations_total {}\n\n",
            pc_stats.ddl_invalidations);
    }

    if (brute_force_protector_) {
        output += std::format(
            "# HELP sql_proxy_auth_failures_total Authentication failures tracked by brute force protector\n"
            "# TYPE sql_proxy_auth_failures_total counter\n"
            "sql_proxy_auth_failures_total {}\n\n"
            "# HELP sql_proxy_auth_blocks_total Requests blocked by brute force protector\n"
            "# TYPE sql_proxy_auth_blocks_total counter\n"
            "sql_proxy_auth_blocks_total {}\n\n",
            brute_force_protector_->total_failures(),
            brute_force_protector_->total_blocks());
    }

    output += std::format(
        "# HELP sql_proxy_ip_blocked_total Requests blocked by IP allowlist\n"
        "# TYPE sql_proxy_ip_blocked_total counter\n"
        "sql_proxy_ip_blocked_total {}\n\n",
        s_ip_blocks.load(std::memory_order_relaxed));

    const auto cost_estimator = pipeline_->get_query_cost_estimator();
    if (cost_estimator && cost_estimator->is_enabled()) {
        output += std::format(
            "# HELP sql_proxy_query_cost_rejected_total Queries rejected by cost estimator\n"
            "# TYPE sql_proxy_query_cost_rejected_total counter\n"
            "sql_proxy_query_cost_rejected_total {}\n\n"
            "# HELP sql_proxy_query_cost_estimated_total Queries estimated by cost estimator\n"
            "# TYPE sql_proxy_query_cost_estimated_total counter\n"
            "sql_proxy_query_cost_estimated_total {}\n\n",
            cost_estimator->total_rejected(), cost_estimator->total_estimated());
    }

    if (schema_drift_detector_ && schema_drift_detector_->is_enabled()) {
        output += std::format(
            "# HELP sql_proxy_schema_drifts_total Total schema drifts detected\n"
            "# TYPE sql_proxy_schema_drifts_total counter\n"
            "sql_proxy_schema_drifts_total {}\n\n"
            "# HELP sql_proxy_schema_drift_checks_total Schema drift checks performed\n"
            "# TYPE sql_proxy_schema_drift_checks_total counter\n"
            "sql_proxy_schema_drift_checks_total {}\n\n",
            schema_drift_detector_->total_drifts(),
            schema_drift_detector_->checks_performed());
    }

    const auto arc = pipeline_->get_adaptive_rate_controller();
    if (arc) {
        const auto arc_stats = arc->get_stats();
        output += std::format(
            "# HELP sql_proxy_adaptive_rate_current_tps Current adaptive rate limit TPS\n"
            "# TYPE sql_proxy_adaptive_rate_current_tps gauge\n"
            "sql_proxy_adaptive_rate_current_tps {}\n\n"
            "# HELP sql_proxy_adaptive_rate_p95_us Approximate P95 latency (bucket midpoint ms)\n"
            "# TYPE sql_proxy_adaptive_rate_p95_us gauge\n"
            "sql_proxy_adaptive_rate_p95_us {}\n\n"
            "# HELP sql_proxy_adaptive_rate_adjustments_total Rate adjustments performed\n"
            "# TYPE sql_proxy_adaptive_rate_adjustments_total counter\n"
            "sql_proxy_adaptive_rate_adjustments_total {}\n\n"
            "# HELP sql_proxy_adaptive_rate_throttle_events_total Times reduced to 40%%\n"
            "# TYPE sql_proxy_adaptive_rate_throttle_events_total counter\n"
            "sql_proxy_adaptive_rate_throttle_events_total {}\n\n"
            "# HELP sql_proxy_adaptive_rate_protect_events_total Times reduced to 10%%\n"
            "# TYPE sql_proxy_adaptive_rate_protect_events_total counter\n"
            "sql_proxy_adaptive_rate_protect_events_total {}\n\n",
            arc_stats.current_tps, arc_stats.p95_bucket_ms,
            arc_stats.adjustments_total,
            arc_stats.throttle_events, arc_stats.protect_events);
    }

    output += "# HELP sql_proxy_info Build information\n"
              "# TYPE sql_proxy_info gauge\n"
              "sql_proxy_info{version=\"1.0.0\"} 1\n";

    return output;
}

// ============================================================================
// Handler: POST /policies/reload
// ============================================================================

void HttpServer::handle_policies_reload(const httplib::Request& req, httplib::Response& res) {
    try {
        if (!require_admin(admin_token_, req, res)) return;

        const std::string config_path = "config/proxy.toml";
        const auto load_result = PolicyLoader::load_from_file(config_path);

        if (!load_result.success) {
            res.status = httplib::StatusCode::BadRequest_400;
            res.set_content(
                std::format(R"({{"success":false,"error":"{}"}})", load_result.error_message),
                http::kJsonContentType);
            return;
        }

        pipeline_->get_policy_engine()->reload_policies(load_result.policies);

        res.status = httplib::StatusCode::OK_200;
        res.set_content(
            std::format(R"({{"success":true,"policies_loaded":{}}})", load_result.policies.size()),
            http::kJsonContentType);

        utils::log::info(std::format("Policies reloaded: {} policies loaded", load_result.policies.size()));

    } catch (const std::exception& e) {
        res.status = httplib::StatusCode::InternalServerError_500;
        res.set_content(
            std::format(R"({{"success":false,"error":"{}"}})", e.what()),
            http::kJsonContentType);
    }
}

// ============================================================================
// Handler: POST /api/v1/config/validate
// ============================================================================

void HttpServer::handle_config_validate(const httplib::Request& req, httplib::Response& res) {
    if (!require_admin(admin_token_, req, res)) return;
    try {
        const auto result = ConfigLoader::load_from_string(req.body);
        if (result.success) {
            res.set_content(R"({"valid":true,"errors":[]})", http::kJsonContentType);
        } else {
            res.set_content(
                std::format(R"({{"valid":false,"errors":["{}"]}})", result.error_message),
                http::kJsonContentType);
        }
    } catch (const std::exception& e) {
        res.set_content(
            std::format(R"({{"valid":false,"errors":["{}"]}})", e.what()),
            http::kJsonContentType);
    }
}

// ============================================================================
// Handler: GET /api/v1/slow-queries
// ============================================================================

void HttpServer::handle_slow_queries(const httplib::Request& req, httplib::Response& res) {
    if (!require_admin(admin_token_, req, res)) return;
    const auto tracker = pipeline_->get_slow_query_tracker();
    if (!tracker || !tracker->is_enabled()) {
        res.set_content(R"({"slow_queries":[],"total_slow_queries":0,"enabled":false})", http::kJsonContentType);
        return;
    }
    const auto recent = tracker->get_recent(100);
    std::string json = std::format("{{\"slow_queries\":[");
    for (size_t i = 0; i < recent.size(); ++i) {
        if (i > 0) json += ",";
        const auto& sq = recent[i];
        json += std::format(
            "{{\"user\":\"{}\",\"database\":\"{}\",\"execution_time_us\":{}}}",
            sq.user, sq.database, sq.execution_time.count());
    }
    json += std::format("],\"total_slow_queries\":{},\"threshold_ms\":{},\"enabled\":true}}",
        tracker->total_slow_queries(), tracker->threshold_ms());
    res.set_content(json, http::kJsonContentType);
}

// ============================================================================
// Handler: GET /api/v1/circuit-breakers
// ============================================================================

void HttpServer::handle_circuit_breakers(const httplib::Request& req, httplib::Response& res) {
    if (!require_admin(admin_token_, req, res)) return;
    const auto cb = pipeline_->get_circuit_breaker();
    if (!cb) {
        res.set_content(R"({"breakers":[]})", http::kJsonContentType);
        return;
    }
    const auto stats = cb->get_stats();
    const auto events = cb->get_recent_events();
    const char* state_str = (stats.state == CircuitState::CLOSED) ? "closed" :
                            (stats.state == CircuitState::OPEN) ? "open" : "half_open";

    std::string events_json = "[";
    for (size_t i = 0; i < events.size(); ++i) {
        if (i > 0) events_json += ",";
        const auto& e = events[i];
        const char* from_str = (e.from == CircuitState::CLOSED) ? "closed" :
                               (e.from == CircuitState::OPEN) ? "open" : "half_open";
        const char* to_str = (e.to == CircuitState::CLOSED) ? "closed" :
                             (e.to == CircuitState::OPEN) ? "open" : "half_open";
        events_json += std::format(
            R"({{"from":"{}","to":"{}","breaker":"{}"}})",
            from_str, to_str, e.breaker_name);
    }
    events_json += "]";

    const auto json = std::format(
        R"({{"breakers":[{{"name":"{}","state":"{}","failure_count":{},"success_count":{},"infrastructure_failures":{},"application_failures":{},"transient_failures":{},"recent_events":{}}}]}})",
        cb->name(), state_str, stats.failure_count, stats.success_count,
        stats.infrastructure_failure_count, stats.application_failure_count,
        stats.transient_failure_count, events_json);
    res.set_content(json, http::kJsonContentType);
}

// ============================================================================
// Compliance handlers
// ============================================================================

void HttpServer::handle_pii_report(const httplib::Request& req, httplib::Response& res) {
    if (!require_admin(admin_token_, req, res)) return;
    if (!compliance_reporter_) {
        res.status = httplib::StatusCode::ServiceUnavailable_503;
        res.set_content(R"({"success":false,"error":"Compliance reporter not configured"})", http::kJsonContentType);
        return;
    }
    const auto report = compliance_reporter_->generate_pii_report();
    res.set_content(ComplianceReporter::pii_report_to_json(report), http::kJsonContentType);
}

void HttpServer::handle_security_summary(const httplib::Request& req, httplib::Response& res) {
    if (!require_admin(admin_token_, req, res)) return;
    if (!compliance_reporter_) {
        res.status = httplib::StatusCode::ServiceUnavailable_503;
        res.set_content(R"({"success":false,"error":"Compliance reporter not configured"})", http::kJsonContentType);
        return;
    }
    const auto summary = compliance_reporter_->generate_security_summary();
    res.set_content(ComplianceReporter::security_summary_to_json(summary), http::kJsonContentType);
}

void HttpServer::handle_lineage(const httplib::Request& req, httplib::Response& res) {
    if (!require_admin(admin_token_, req, res)) return;
    if (!lineage_tracker_) {
        res.status = httplib::StatusCode::ServiceUnavailable_503;
        res.set_content(R"({"success":false,"error":"Lineage tracker not configured"})", http::kJsonContentType);
        return;
    }
    const auto summaries = lineage_tracker_->get_summaries();
    std::string json = "{\"summaries\":[";
    for (size_t i = 0; i < summaries.size(); ++i) {
        if (i > 0) json += ",";
        const auto& s = summaries[i];
        json += std::format(
            "{{\"column_key\":\"{}\",\"classification\":\"{}\","
            "\"total_accesses\":{},\"masked_accesses\":{},\"unmasked_accesses\":{},"
            "\"unique_users\":{}}}",
            s.column_key, s.classification,
            s.total_accesses, s.masked_accesses, s.unmasked_accesses,
            s.accessing_users.size());
    }
    json += std::format("],\"total_events\":{}}}", lineage_tracker_->total_events());
    res.set_content(json, http::kJsonContentType);
}

void HttpServer::handle_data_subject_access(const httplib::Request& req, httplib::Response& res) {
    if (!require_admin(admin_token_, req, res)) return;
    if (!lineage_tracker_) {
        res.status = httplib::StatusCode::ServiceUnavailable_503;
        res.set_content(R"({"success":false,"error":"Lineage tracker not configured"})", http::kJsonContentType);
        return;
    }

    const std::string subject_user = req.get_param_value("user");
    if (subject_user.empty()) {
        res.status = httplib::StatusCode::BadRequest_400;
        res.set_content(R"({"success":false,"error":"Missing required parameter: user"})", http::kJsonContentType);
        return;
    }

    const auto events = lineage_tracker_->get_events(subject_user, "", 1000);
    std::string json = std::format("{{\"subject\":\"{}\",\"events\":[", subject_user);
    for (size_t i = 0; i < events.size(); ++i) {
        if (i > 0) json += ",";
        const auto& e = events[i];
        json += std::format(
            "{{\"timestamp\":\"{}\",\"database\":\"{}\",\"table\":\"{}\","
            "\"column\":\"{}\",\"classification\":\"{}\",\"access_type\":\"{}\","
            "\"was_masked\":{}}}",
            e.timestamp, e.database, e.table,
            e.column, e.classification, e.access_type,
            utils::booltostr(e.was_masked));
    }
    json += std::format("],\"total_events\":{}}}", events.size());
    res.set_content(json, http::kJsonContentType);
}

// ============================================================================
// Schema management handlers
// ============================================================================

void HttpServer::handle_schema_history(const httplib::Request& req, httplib::Response& res) {
    if (!require_admin(admin_token_, req, res)) return;
    const auto history = schema_manager_->get_history();
    std::string json = "{\"history\":[";
    for (size_t i = 0; i < history.size(); ++i) {
        if (i > 0) json += ",";
        const auto& h = history[i];
        json += std::format(
            "{{\"id\":\"{}\",\"user\":\"{}\",\"database\":\"{}\","
            "\"table\":\"{}\",\"status\":\"{}\"}}",
            h.id, h.user, h.database, h.table, h.status);
    }
    json += std::format("],\"total\":{}}}", history.size());
    res.set_content(json, http::kJsonContentType);
}

void HttpServer::handle_schema_pending(const httplib::Request& req, httplib::Response& res) {
    if (!require_admin(admin_token_, req, res)) return;
    const auto pending = schema_manager_->get_pending();
    std::string json = "{\"pending\":[";
    for (size_t i = 0; i < pending.size(); ++i) {
        if (i > 0) json += ",";
        const auto& p = pending[i];
        json += std::format(
            "{{\"id\":\"{}\",\"user\":\"{}\",\"database\":\"{}\","
            "\"table\":\"{}\",\"status\":\"{}\"}}",
            p.id, p.user, p.database, p.table, p.status);
    }
    json += std::format("],\"total\":{}}}", pending.size());
    res.set_content(json, http::kJsonContentType);
}

void HttpServer::handle_schema_approve(const httplib::Request& req, httplib::Response& res) {
    if (!require_admin(admin_token_, req, res)) return;
    const auto id = std::string(parse_json_field(req.body, "id"));
    const auto admin = std::string(parse_json_field(req.body, "admin"));
    if (id.empty()) {
        res.status = httplib::StatusCode::BadRequest_400;
        res.set_content(R"({"success":false,"error":"Missing field: id"})", http::kJsonContentType);
        return;
    }
    const bool ok = schema_manager_->approve(id, admin.empty() ? "admin" : admin);
    res.set_content(
        std::format(R"({{"success":{}}})", utils::booltostr(ok)),
        http::kJsonContentType);
}

void HttpServer::handle_schema_reject(const httplib::Request& req, httplib::Response& res) {
    if (!require_admin(admin_token_, req, res)) return;
    const auto id = std::string(parse_json_field(req.body, "id"));
    const auto admin = std::string(parse_json_field(req.body, "admin"));
    if (id.empty()) {
        res.status = httplib::StatusCode::BadRequest_400;
        res.set_content(R"({"success":false,"error":"Missing field: id"})", http::kJsonContentType);
        return;
    }
    const bool ok = schema_manager_->reject(id, admin.empty() ? "admin" : admin);
    res.set_content(
        std::format(R"({{"success":{}}})", utils::booltostr(ok)),
        http::kJsonContentType);
}

void HttpServer::handle_schema_drift(const httplib::Request& req, httplib::Response& res) {
    if (!require_admin(admin_token_, req, res)) return;
    if (!schema_drift_detector_ || !schema_drift_detector_->is_enabled()) {
        res.set_content(R"({"drift_events":[],"total_drifts":0,"enabled":false})", http::kJsonContentType);
        return;
    }
    const auto events = schema_drift_detector_->get_drift_events();
    std::string json = std::format("{{\"drift_events\":[");
    for (size_t i = 0; i < events.size(); ++i) {
        if (i > 0) json += ",";
        const auto& e = events[i];
        json += std::format(
            "{{\"timestamp\":\"{}\",\"change_type\":\"{}\",\"table\":\"{}\","
            "\"column\":\"{}\",\"old_type\":\"{}\",\"new_type\":\"{}\"}}",
            e.timestamp, e.change_type, e.table_name,
            e.column_name, e.old_type, e.new_type);
    }
    json += std::format("],\"total_drifts\":{},\"checks_performed\":{},\"enabled\":true}}",
        schema_drift_detector_->total_drifts(),
        schema_drift_detector_->checks_performed());
    res.set_content(json, http::kJsonContentType);
}

// ============================================================================
// Handler: POST /api/v1/graphql
// ============================================================================

void HttpServer::handle_graphql(const httplib::Request& req, httplib::Response& res) {
    try {
        const auto query_sv = parse_json_field(req.body, "query");
        const auto user_sv = parse_json_field(req.body, "user");
        const auto db_sv = parse_json_field(req.body, "database");

        if (query_sv.empty()) {
            res.status = httplib::StatusCode::BadRequest_400;
            res.set_content(R"({"errors":[{"message":"Missing required field: query"}]})", http::kJsonContentType);
            return;
        }

        const std::string user = user_sv.empty() ? "anonymous" : std::string(user_sv);
        const std::string database = db_sv.empty() ? "testdb" : std::string(db_sv);

        const auto user_info = validate_user(user);
        std::vector<std::string> roles;
        if (user_info) roles = user_info->roles;

        const auto result_json = graphql_handler_->execute(
            std::string(query_sv), user, roles, database);
        res.set_content(result_json, http::kJsonContentType);
    } catch (const std::exception& e) {
        res.status = httplib::StatusCode::BadRequest_400;
        res.set_content(
            std::format(R"({{"errors":[{{"message":"{}"}}]}})", e.what()),
            http::kJsonContentType);
    }
}

} // namespace sqlproxy
