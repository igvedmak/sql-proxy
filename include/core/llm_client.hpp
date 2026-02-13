#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace sqlproxy {

// LLM use case types
enum class LlmUseCase : uint8_t {
    POLICY_GENERATOR,
    ANOMALY_EXPLANATION,
    NL_TO_POLICY,
    SQL_INTENT_CLASSIFICATION
};

[[nodiscard]] inline const char* llm_use_case_to_string(LlmUseCase uc) {
    switch (uc) {
        case LlmUseCase::POLICY_GENERATOR:         return "policy_generator";
        case LlmUseCase::ANOMALY_EXPLANATION:       return "anomaly_explanation";
        case LlmUseCase::NL_TO_POLICY:              return "nl_to_policy";
        case LlmUseCase::SQL_INTENT_CLASSIFICATION: return "sql_intent_classification";
        default:                                     return "unknown";
    }
}

struct LlmRequest {
    LlmUseCase use_case = LlmUseCase::POLICY_GENERATOR;
    std::string prompt;
    std::string context;
    std::string model = "gpt-4";
    double temperature = 0.3;
    int max_tokens = 2048;
};

struct LlmResponse {
    bool success = false;
    std::string content;
    std::string error;
    std::string model_used;
    uint32_t prompt_tokens = 0;
    uint32_t completion_tokens = 0;
    bool from_cache = false;
    std::chrono::milliseconds latency{0};
};

/**
 * @brief LLM client for AI-powered proxy features.
 *
 * Uses OpenAI-compatible API format via httplib::Client.
 * Features:
 * - Response caching by query fingerprint
 * - Rate limiting on LLM API calls
 * - Graceful degradation if LLM unavailable
 * - System prompts per use case
 */
class LlmClient {
public:
    struct Config {
        bool enabled = false;
        std::string endpoint = "https://api.openai.com";
        std::string api_key;
        std::string default_model = "gpt-4";
        uint32_t timeout_ms = 30000;
        uint32_t max_retries = 2;
        uint32_t max_requests_per_minute = 60;
        bool cache_enabled = true;
        size_t cache_max_entries = 1000;
        uint32_t cache_ttl_seconds = 3600;
    };

    LlmClient();
    explicit LlmClient(Config config);

    [[nodiscard]] bool is_enabled() const { return config_.enabled; }

    // Core API
    [[nodiscard]] LlmResponse complete(const LlmRequest& request);

    // Convenience methods
    [[nodiscard]] LlmResponse generate_policy(const std::string& query_sample,
                                               const std::string& context);
    [[nodiscard]] LlmResponse explain_anomaly(const std::string& description);
    [[nodiscard]] LlmResponse nl_to_policy(const std::string& natural_language);
    [[nodiscard]] LlmResponse classify_intent(const std::string& sql);

    // System prompt access (for testing)
    [[nodiscard]] static std::string get_system_prompt(LlmUseCase use_case);

    // Cache key generation (for testing)
    [[nodiscard]] static std::string cache_key(LlmUseCase use_case,
                                                const std::string& input);

    struct Stats {
        uint64_t total_requests = 0;
        uint64_t cache_hits = 0;
        uint64_t api_calls = 0;
        uint64_t api_errors = 0;
        uint64_t rate_limited = 0;
    };

    [[nodiscard]] Stats get_stats() const;

private:
    [[nodiscard]] LlmResponse call_api(const std::string& system_prompt,
                                        const std::string& user_prompt,
                                        const std::string& model,
                                        double temperature,
                                        int max_tokens);

    [[nodiscard]] bool check_rate_limit();

    Config config_;

    // Response cache
    struct CacheEntry {
        LlmResponse response;
        std::chrono::steady_clock::time_point expires_at;
    };
    std::unordered_map<std::string, CacheEntry> cache_;
    mutable std::shared_mutex cache_mutex_;

    // Rate limiting
    std::atomic<uint32_t> requests_this_minute_{0};
    std::chrono::steady_clock::time_point minute_start_ =
        std::chrono::steady_clock::now();
    std::mutex rate_mutex_;

    // Stats
    std::atomic<uint64_t> total_requests_{0};
    std::atomic<uint64_t> cache_hits_{0};
    std::atomic<uint64_t> api_calls_{0};
    std::atomic<uint64_t> api_errors_{0};
    std::atomic<uint64_t> rate_limited_{0};
};

} // namespace sqlproxy
