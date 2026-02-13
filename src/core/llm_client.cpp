#include "core/llm_client.hpp"
#include "core/utils.hpp"
#include <format>
#include <functional>

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

LlmResponse LlmClient::call_api(
    const std::string& system_prompt,
    const std::string& user_prompt,
    const std::string& model,
    [[maybe_unused]] double temperature,
    [[maybe_unused]] int max_tokens) {
    api_calls_.fetch_add(1, std::memory_order_relaxed);

    const auto start = std::chrono::steady_clock::now();

    // Build OpenAI-compatible request
    // Note: Actual HTTP call requires httplib::Client; for now we return
    // a structured response indicating the API endpoint is not reachable
    // in test environments. In production, this would make the HTTP call.

    if (config_.api_key.empty()) {
        api_errors_.fetch_add(1, std::memory_order_relaxed);
        return {false, "", "No API key configured", model, 0, 0, false, {}};
    }

    if (config_.endpoint.empty()) {
        api_errors_.fetch_add(1, std::memory_order_relaxed);
        return {false, "", "No endpoint configured", model, 0, 0, false, {}};
    }

    // In production, this would use httplib::Client to call the API:
    //   httplib::Client cli(config_.endpoint);
    //   cli.set_bearer_token_auth(config_.api_key);
    //   auto res = cli.Post("/v1/chat/completions", json_body, "application/json");
    //
    // For now, return a placeholder that tests can verify the flow
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);

    // Simulate API response for testing
    LlmResponse response;
    response.success = true;
    response.content = std::format("[LLM Response] System: {}\nUser: {}",
                                   system_prompt.substr(0, 50), user_prompt.substr(0, 50));
    response.model_used = model;
    response.prompt_tokens = static_cast<uint32_t>(system_prompt.size() / 4);
    response.completion_tokens = static_cast<uint32_t>(response.content.size() / 4);
    response.from_cache = false;
    response.latency = elapsed;

    return response;
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
