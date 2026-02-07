#pragma once

#include "core/types.hpp"
#include "server/http_server.hpp"  // UserInfo

#include <nlohmann/json.hpp>

#include <string>
#include <vector>
#include <unordered_map>
#include <optional>

namespace sqlproxy {

// ============================================================================
// Rate Limiting Config (mirrors TOML hierarchy)
// ============================================================================

struct PerUserRateLimit {
    std::string user;
    uint32_t tokens_per_second;
    uint32_t burst_capacity;
};

struct PerDatabaseRateLimit {
    std::string database;
    uint32_t tokens_per_second;
    uint32_t burst_capacity;
};

struct PerUserPerDatabaseRateLimit {
    std::string user;
    std::string database;
    uint32_t tokens_per_second;
    uint32_t burst_capacity;
};

struct RateLimitingConfig {
    bool enabled = true;

    // Level 1: Global
    uint32_t global_tokens_per_second = 50000;
    uint32_t global_burst_capacity = 10000;

    // Level 2: Per-User overrides
    std::vector<PerUserRateLimit> per_user;
    uint32_t per_user_default_tokens_per_second = 100;
    uint32_t per_user_default_burst_capacity = 20;

    // Level 3: Per-Database
    std::vector<PerDatabaseRateLimit> per_database;

    // Level 4: Per-User-Per-Database
    std::vector<PerUserPerDatabaseRateLimit> per_user_per_database;
};

// ============================================================================
// Classifier Config
// ============================================================================

struct ClassifierConfig {
    std::string type;
    std::string strategy;
    std::vector<std::string> patterns;
    std::string data_validation_regex;
    int sample_size = 0;
    double confidence_threshold = 0.0;
};

// ============================================================================
// Logging Config
// ============================================================================

struct LoggingConfig {
    std::string level = "info";
    std::string file;
    bool async_logging = true;
};

// ============================================================================
// Circuit Breaker Config
// ============================================================================

struct CircuitBreakerConfig {
    bool enabled = true;
    int failure_threshold = 10;
    int success_threshold = 5;
    int timeout_ms = 60000;
    int half_open_max_calls = 3;
};

// ============================================================================
// Allocator Config
// ============================================================================

struct AllocatorConfig {
    bool enabled = true;
    size_t initial_size_bytes = 1024;
    size_t max_size_bytes = 65536;
};

// ============================================================================
// Metrics Config
// ============================================================================

struct MetricsConfig {
    bool enabled = true;
    std::string endpoint = "/metrics";
    int export_interval_ms = 5000;
};

// ============================================================================
// Config Watcher Config
// ============================================================================

struct ConfigWatcherConfig {
    bool enabled = true;
    int poll_interval_seconds = 5;
};

// ============================================================================
// ProxyConfig - Complete parsed configuration
// ============================================================================

struct ProxyConfig {
    ServerConfig server;
    LoggingConfig logging;
    std::vector<DatabaseConfig> databases;
    std::unordered_map<std::string, UserInfo> users;
    std::vector<Policy> policies;
    RateLimitingConfig rate_limiting;
    CacheConfig cache;
    AuditConfig audit;
    std::vector<ClassifierConfig> classifiers;
    CircuitBreakerConfig circuit_breaker;
    AllocatorConfig allocator;
    MetricsConfig metrics;
    ConfigWatcherConfig config_watcher;
};

// ============================================================================
// TOML Parser - Lightweight subset parser using nlohmann::json
// ============================================================================

/**
 * @brief Parse a TOML file into nlohmann::json representation
 *
 * Supports the subset of TOML used by proxy.toml:
 * - [section] headers
 * - [section.subsection] dotted headers
 * - [[array]] repeated sections
 * - [[section.array]] nested array sections
 * - key = "value" strings
 * - key = 123 integers
 * - key = 1.5 floats
 * - key = true/false booleans
 * - key = ["a", "b"] inline string arrays
 * - # comments
 * - Multi-line arrays with [ ... ]
 */
namespace toml {

/**
 * @brief Parse TOML content string into JSON
 * @param content TOML text
 * @return Parsed JSON object
 * @throws std::runtime_error on parse failure
 */
[[nodiscard]] nlohmann::json parse_string(const std::string& content);

/**
 * @brief Parse TOML file into JSON
 * @param file_path Path to .toml file
 * @return Parsed JSON object
 * @throws std::runtime_error on file I/O or parse failure
 */
[[nodiscard]] nlohmann::json parse_file(const std::string& file_path);

} // namespace toml

// ============================================================================
// ConfigLoader - Extract typed config from parsed TOML
// ============================================================================

class ConfigLoader {
public:
    struct LoadResult {
        bool success;
        std::string error_message;
        ProxyConfig config;

        static LoadResult ok(ProxyConfig cfg) {
            LoadResult result;
            result.success = true;
            result.config = std::move(cfg);
            return result;
        }

        static LoadResult error(std::string message) {
            LoadResult result;
            result.success = false;
            result.error_message = std::move(message);
            return result;
        }
    };

    /**
     * @brief Load complete config from TOML file
     * @param config_path Path to proxy.toml
     * @return LoadResult with parsed config or error
     */
    [[nodiscard]] static LoadResult load_from_file(const std::string& config_path);

    /**
     * @brief Load complete config from TOML string
     * @param toml_content TOML content
     * @return LoadResult with parsed config or error
     */
    [[nodiscard]] static LoadResult load_from_string(const std::string& toml_content);

private:
    static ServerConfig extract_server(const nlohmann::json& root);
    static LoggingConfig extract_logging(const nlohmann::json& root);
    static std::vector<DatabaseConfig> extract_databases(const nlohmann::json& root);
    static std::unordered_map<std::string, UserInfo> extract_users(const nlohmann::json& root);
    static std::vector<Policy> extract_policies(const nlohmann::json& root);
    static RateLimitingConfig extract_rate_limiting(const nlohmann::json& root);
    static CacheConfig extract_cache(const nlohmann::json& root);
    static AuditConfig extract_audit(const nlohmann::json& root);
    static std::vector<ClassifierConfig> extract_classifiers(const nlohmann::json& root);
    static CircuitBreakerConfig extract_circuit_breaker(const nlohmann::json& root);
    static AllocatorConfig extract_allocator(const nlohmann::json& root);
    static MetricsConfig extract_metrics(const nlohmann::json& root);
    static ConfigWatcherConfig extract_config_watcher(const nlohmann::json& root);

    // Helper: parse statement type string to enum
    static std::optional<StatementType> parse_statement_type(const std::string& type_str);

    // Helper: parse action string to Decision enum
    static std::optional<Decision> parse_action(const std::string& action_str);
};

} // namespace sqlproxy
