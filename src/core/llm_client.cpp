#include "core/llm_client.hpp"
#include "core/utils.hpp"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include "../third_party/cpp-httplib/httplib.h"
#pragma GCC diagnostic pop

#include <format>
#include <functional>
#include <thread>

namespace sqlproxy {

// ============================================================================
// Construction
// ============================================================================

LlmClient::LlmClient() = default;

LlmClient::LlmClient(Config config)
    : config_(std::move(config)) {}

// ============================================================================
// System Prompts
// ============================================================================

std::string LlmClient::get_system_prompt(LlmUseCase use_case) {
    switch (use_case) {
        case LlmUseCase::POLICY_GENERATOR:
            return "You are a SQL proxy policy generator. Analyze the given SQL queries "
                   "and generate TOML policy entries. Output valid TOML that can be added "
                   "to the proxy configuration. Each policy should specify table access "
                   "(allow/block), column restrictions, and appropriate user roles. "
                   "Format: [[policies]]\nuser = \"...\"\ntable = \"...\"\naccess = \"allow|block\"";

        case LlmUseCase::ANOMALY_EXPLANATION:
            return "You are a security analyst for a SQL proxy. Explain the given anomaly "
                   "in clear, concise language. Describe what happened, why it's unusual, "
                   "the potential risk, and recommended actions. Be specific about the "
                   "user, query pattern, timing, and any indicators of compromise.";

        case LlmUseCase::NL_TO_POLICY:
            return "You are a SQL proxy policy translator. Convert natural language "
                   "descriptions of access control requirements into valid TOML policy "
                   "configuration. Output ONLY valid TOML, no explanations. "
                   "Format: [[policies]]\nuser = \"...\"\ntable = \"...\"\naccess = \"allow|block\"\n"
                   "columns = [\"col1\", \"col2\"]  # optional column restrictions";

        case LlmUseCase::SQL_INTENT_CLASSIFICATION:
            return "You are a SQL security classifier. Classify the intent of the given "
                   "SQL query into one of these categories: LEGITIMATE, DATA_EXFILTRATION, "
                   "PRIVILEGE_ESCALATION, INJECTION_ATTEMPT, SCHEMA_MANIPULATION, "
                   "DENIAL_OF_SERVICE, RECONNAISSANCE. Provide the classification and "
                   "a brief explanation. Format: CLASSIFICATION: <category>\\nEXPLANATION: <text>";

        case LlmUseCase::NL_TO_SQL:
            return "You are a SQL query generator for PostgreSQL. Given a natural language "
                   "question and a database schema, generate a single valid PostgreSQL SELECT "
                   "query that answers the question. Output ONLY the SQL query, no explanation, "
                   "no markdown code fences, no comments. The query must be safe (no DDL, no "
                   "mutations, only SELECT). Use the exact table and column names from the schema.";

        default:
            return "You are a helpful assistant for SQL proxy administration.";
    }
}

// ============================================================================
// Cache Key Generation
// ============================================================================

std::string LlmClient::cache_key(LlmUseCase use_case, const std::string& input) {
    // Use std::hash for cache key — not cryptographic, but fast
    const auto hash = std::hash<std::string>{}(input);
    return std::format("{}:{:016x}",
                       static_cast<int>(use_case), hash);
}

// ============================================================================
// Rate Limiting
// ============================================================================

bool LlmClient::check_rate_limit() {
    std::lock_guard lock(rate_mutex_);
    const auto now = std::chrono::steady_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - minute_start_);

    if (elapsed.count() >= 60) {
        // New minute window
        minute_start_ = now;
        requests_this_minute_.store(0, std::memory_order_relaxed);
    }

    const uint32_t current = requests_this_minute_.load(std::memory_order_relaxed);
    if (current >= config_.max_requests_per_minute) {
        return false;
    }

    requests_this_minute_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

// ============================================================================
// Core API
// ============================================================================

LlmResponse LlmClient::complete(const LlmRequest& request) {
    total_requests_.fetch_add(1, std::memory_order_relaxed);

    if (!config_.enabled) {
        return {false, "", "LLM client is disabled", "", 0, 0, false, {}};
    }

    // Check cache (read path — shared lock)
    if (config_.cache_enabled) {
        const auto key = cache_key(request.use_case, request.prompt + request.context);

        std::shared_lock lock(cache_mutex_);
        const auto it = cache_.find(key);
        if (it != cache_.end()) {
            const auto now = std::chrono::steady_clock::now();
            if (now < it->second.expires_at) {
                cache_hits_.fetch_add(1, std::memory_order_relaxed);
                auto response = it->second.response;
                response.from_cache = true;
                return response;
            }
        }
    }

    // Rate limit check
    if (!check_rate_limit()) {
        rate_limited_.fetch_add(1, std::memory_order_relaxed);
        return {false, "", "Rate limited: too many LLM API requests", "", 0, 0, false, {}};
    }

    // Call LLM API
    const auto system_prompt = get_system_prompt(request.use_case);
    const auto model = request.model.empty() ? config_.default_model : request.model;
    auto response = call_api(system_prompt, request.prompt + "\n\nContext:\n" + request.context,
                             model, request.temperature, request.max_tokens);

    // Cache successful response
    if (response.success && config_.cache_enabled) {
        const auto key = cache_key(request.use_case, request.prompt + request.context);
        const auto expires = std::chrono::steady_clock::now() +
                             std::chrono::seconds(config_.cache_ttl_seconds);

        std::unique_lock lock(cache_mutex_);

        // Evict oldest entries if at capacity
        if (cache_.size() >= config_.cache_max_entries) {
            auto oldest_it = cache_.begin();
            auto oldest_time = oldest_it->second.expires_at;
            for (auto it = cache_.begin(); it != cache_.end(); ++it) {
                if (it->second.expires_at < oldest_time) {
                    oldest_it = it;
                    oldest_time = it->second.expires_at;
                }
            }
            cache_.erase(oldest_it);
        }

        cache_[key] = {response, expires};
    }

    return response;
}

// ============================================================================
// LLM Response Parsing
// ============================================================================

static std::string extract_content(const std::string& body, const std::string& provider) {
    using utils::find_unescaped_quote;
    using utils::unescape_json;
    if (provider == "anthropic") {
        // Anthropic: {"content":[{"type":"text","text":"..."}]}
        const auto text_pos = body.rfind("\"text\"");
        if (text_pos != std::string::npos) {
            const auto colon = body.find(':', text_pos + 5);
            if (colon == std::string::npos) return body;
            const auto quote_start = body.find('"', colon + 1);
            if (quote_start == std::string::npos) return body;
            const auto quote_end = find_unescaped_quote(body, quote_start + 1);
            if (quote_end != std::string::npos) {
                return unescape_json(body.substr(quote_start + 1, quote_end - quote_start - 1));
            }
        }
    } else {
        // OpenAI: {"choices":[{"message":{"content":"..."}}]}
        const auto last_content = body.rfind("\"content\"");
        if (last_content != std::string::npos) {
            const auto colon = body.find(':', last_content + 8);
            if (colon == std::string::npos) return body;
            // Skip whitespace after colon
            auto val_start = colon + 1;
            while (val_start < body.size() && (body[val_start] == ' ' || body[val_start] == '\n')) ++val_start;
            if (val_start < body.size() && body[val_start] == '"') {
                const auto quote_end = find_unescaped_quote(body, val_start + 1);
                if (quote_end != std::string::npos) {
                    return unescape_json(body.substr(val_start + 1, quote_end - val_start - 1));
                }
            }
        }
    }
    return body;
}

// ============================================================================
// API Call
// ============================================================================

LlmResponse LlmClient::call_api(
    const std::string& system_prompt,
    const std::string& user_prompt,
    const std::string& model,
    double temperature,
    int max_tokens) {
    api_calls_.fetch_add(1, std::memory_order_relaxed);

    const auto start = std::chrono::steady_clock::now();

    if (config_.api_key.empty()) {
        api_errors_.fetch_add(1, std::memory_order_relaxed);
        return {false, "", "No API key configured", model, 0, 0, false, {}};
    }

    if (config_.endpoint.empty()) {
        api_errors_.fetch_add(1, std::memory_order_relaxed);
        return {false, "", "No endpoint configured", model, 0, 0, false, {}};
    }

    // Build JSON request body
    std::string json_body;
    if (config_.provider == "anthropic") {
        json_body = std::format(
            R"({{"model":"{}","max_tokens":{},"system":"{}","messages":[{{"role":"user","content":"{}"}}]}})",
            model, max_tokens,
            utils::escape_json(system_prompt),
            utils::escape_json(user_prompt));
    } else {
        json_body = std::format(
            R"({{"model":"{}","temperature":{},"max_tokens":{},"messages":[{{"role":"system","content":"{}"}},{{"role":"user","content":"{}"}}]}})",
            model, temperature, max_tokens,
            utils::escape_json(system_prompt),
            utils::escape_json(user_prompt));
    }

    // HTTP client
    httplib::Client cli(config_.endpoint);
    cli.set_connection_timeout(std::chrono::milliseconds(config_.timeout_ms));
    cli.set_read_timeout(std::chrono::milliseconds(config_.timeout_ms));

    httplib::Headers headers;
    std::string path;

    if (config_.provider == "anthropic") {
        headers = {
            {"x-api-key", config_.api_key},
            {"anthropic-version", "2023-06-01"},
            {"content-type", "application/json"}
        };
        path = "/v1/messages";
    } else {
        headers = {
            {"Authorization", "Bearer " + config_.api_key},
            {"content-type", "application/json"}
        };
        path = "/v1/chat/completions";
    }

    // Retry loop
    for (uint32_t attempt = 0; attempt <= config_.max_retries; ++attempt) {
        const auto res = cli.Post(path, headers, json_body, "application/json");

        if (!res) {
            if (attempt < config_.max_retries) continue;
            api_errors_.fetch_add(1, std::memory_order_relaxed);
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            return {false, "", "HTTP request failed: connection error", model, 0, 0, false, elapsed};
        }

        if (res->status == httplib::StatusCode::TooManyRequests_429) {
            if (attempt < config_.max_retries) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1000 * (attempt + 1)));
                continue;
            }
        }

        if (res->status != httplib::StatusCode::OK_200) {
            api_errors_.fetch_add(1, std::memory_order_relaxed);
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            return {false, "", std::format("API error: HTTP {} - {}", res->status,
                    res->body.substr(0, 200)), model, 0, 0, false, elapsed};
        }

        auto content = extract_content(res->body, config_.provider);
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);

        return {true, std::move(content), "", model, 0, 0, false, elapsed};
    }

    api_errors_.fetch_add(1, std::memory_order_relaxed);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    return {false, "", "Max retries exceeded", model, 0, 0, false, elapsed};
}

// ============================================================================
// Convenience Methods
// ============================================================================

LlmResponse LlmClient::generate_policy(const std::string& query_sample,
                                         const std::string& context) {
    LlmRequest req;
    req.use_case = LlmUseCase::POLICY_GENERATOR;
    req.prompt = "Generate access control policies for these SQL queries:\n" + query_sample;
    req.context = context;
    req.temperature = 0.2;
    return complete(req);
}

LlmResponse LlmClient::explain_anomaly(const std::string& description) {
    LlmRequest req;
    req.use_case = LlmUseCase::ANOMALY_EXPLANATION;
    req.prompt = "Explain this anomaly:\n" + description;
    req.temperature = 0.3;
    return complete(req);
}

LlmResponse LlmClient::nl_to_policy(const std::string& natural_language) {
    LlmRequest req;
    req.use_case = LlmUseCase::NL_TO_POLICY;
    req.prompt = natural_language;
    req.temperature = 0.1;
    return complete(req);
}

LlmResponse LlmClient::classify_intent(const std::string& sql) {
    LlmRequest req;
    req.use_case = LlmUseCase::SQL_INTENT_CLASSIFICATION;
    req.prompt = "Classify the intent of this SQL query:\n" + sql;
    req.temperature = 0.0;
    return complete(req);
}

LlmResponse LlmClient::nl_to_sql(const std::string& question,
                                   const std::string& schema_context) {
    LlmRequest req;
    req.use_case = LlmUseCase::NL_TO_SQL;
    req.prompt = question;
    req.context = schema_context;
    req.temperature = 0.0;
    req.max_tokens = 1024;
    return complete(req);
}

// ============================================================================
// Stats
// ============================================================================

LlmClient::Stats LlmClient::get_stats() const {
    return {
        total_requests_.load(std::memory_order_relaxed),
        cache_hits_.load(std::memory_order_relaxed),
        api_calls_.load(std::memory_order_relaxed),
        api_errors_.load(std::memory_order_relaxed),
        rate_limited_.load(std::memory_order_relaxed)
    };
}

} // namespace sqlproxy
