#pragma once

#include "core/types.hpp"
#include "server/http_server.hpp"  // UserInfo
#include "alerting/alert_types.hpp"

#include "core/json.hpp"

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

    // Request queuing (backpressure)
    bool queue_enabled = false;
    uint32_t queue_timeout_ms = 5000;
    uint32_t max_queue_depth = 1000;
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
    int failure_threshold = 15;
    int success_threshold = 5;
    int timeout_ms = 5000;
    int half_open_max_calls = 5;
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
// Security Config (Tier 4)
// ============================================================================

struct SecurityConfig {
    bool injection_detection_enabled = true;
    bool anomaly_detection_enabled = true;
    bool lineage_tracking_enabled = true;
};

// ============================================================================
// Encryption Config (Tier 4)
// ============================================================================

struct EncryptionColumnConfigEntry {
    std::string database;
    std::string table;
    std::string column;
};

struct EncryptionConfig {
    bool enabled = false;
    std::string key_file = "config/encryption_keys.json";
    std::vector<EncryptionColumnConfigEntry> columns;

    // Key manager provider selection
    std::string key_manager_provider = "local";  // "local" | "vault" | "env"
    // Vault
    std::string vault_addr;
    std::string vault_token;
    std::string vault_key_name = "sql-proxy";
    std::string vault_mount = "transit";
    int vault_cache_ttl_seconds = 300;
    // Env
    std::string env_key_var = "ENCRYPTION_KEY";
};

// ============================================================================
// Auth Config (Tier A)
// ============================================================================

struct AuthConfig {
    std::string provider = "api_key";  // "api_key" | "jwt" | "ldap"
    // JWT
    std::string jwt_issuer;
    std::string jwt_audience;
    std::string jwt_secret;
    std::string jwt_roles_claim = "roles";
    // LDAP
    std::string ldap_url;
    std::string ldap_base_dn;
    std::string ldap_bind_dn;
    std::string ldap_bind_password;
    std::string ldap_user_filter = "(uid={})";
    std::string ldap_group_attribute = "memberOf";
};

// ============================================================================
// Tier 5 Config Structs
// ============================================================================

struct TenantConfigEntry {
    bool enabled = false;
    std::string default_tenant = "default";
    std::string header_name = "X-Tenant-Id";
};

struct PluginConfigEntry {
    std::string path;
    std::string type;       // "classifier" or "audit_sink"
    std::string config;     // JSON config string
};

struct SchemaManagementConfigEntry {
    bool enabled = false;
    bool require_approval = false;
    size_t max_history_entries = 1000;
};

struct WireProtocolConfigEntry {
    bool enabled = false;
    std::string host = "0.0.0.0";
    uint16_t port = 5433;
    uint32_t max_connections = 100;
    uint32_t thread_pool_size = 4;
    bool require_password = false;
};

struct GraphQLConfigEntry {
    bool enabled = false;
    std::string endpoint = "/api/v1/graphql";
    uint32_t max_query_depth = 5;
};

struct BinaryRpcConfigEntry {
    bool enabled = false;
    std::string host = "0.0.0.0";
    uint16_t port = 9090;
    uint32_t max_connections = 50;
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
    std::vector<RlsRule> rls_rules;
    std::vector<RewriteRule> rewrite_rules;
    SecurityConfig security;
    EncryptionConfig encryption;

    // Tier 5
    TenantConfigEntry tenants;
    std::vector<PluginConfigEntry> plugins;
    SchemaManagementConfigEntry schema_management;
    WireProtocolConfigEntry wire_protocol;
    GraphQLConfigEntry graphql;
    BinaryRpcConfigEntry binary_rpc;

    // Tier 2 (Operational Maturity)
    AlertingConfig alerting;
    bool dashboard_enabled = true;

    // Tier A (Trust & Safety)
    AuthConfig auth;

    // Tier B (Performance & Efficiency)
    struct AuditSamplingConfig {
        bool enabled = false;
        double default_sample_rate = 1.0;
        double select_sample_rate = 1.0;
        bool always_log_blocked = true;
        bool always_log_writes = true;
        bool always_log_errors = true;
        bool deterministic = true;
    } audit_sampling;

    struct ResultCacheConfig {
        bool enabled = false;
        size_t max_entries = 5000;
        size_t num_shards = 16;
        int ttl_seconds = 60;
        size_t max_result_size_bytes = 1048576;  // 1MB
    } result_cache;
};

// ============================================================================
// TOML Parser - Lightweight subset parser using JsonValue
// ============================================================================

/**
 * @brief Parse a TOML file into JsonValue representation
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
[[nodiscard]] JsonValue parse_string(const std::string& content);

/**
 * @brief Parse TOML file into JSON
 * @param file_path Path to .toml file
 * @return Parsed JSON object
 * @throws std::runtime_error on file I/O or parse failure
 */
[[nodiscard]] JsonValue parse_file(const std::string& file_path);

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
    static ServerConfig extract_server(const JsonValue& root);
    static LoggingConfig extract_logging(const JsonValue& root);
    static std::vector<DatabaseConfig> extract_databases(const JsonValue& root);
    static std::unordered_map<std::string, UserInfo> extract_users(const JsonValue& root);
    static std::vector<Policy> extract_policies(const JsonValue& root);
    static RateLimitingConfig extract_rate_limiting(const JsonValue& root);
    static CacheConfig extract_cache(const JsonValue& root);
    static AuditConfig extract_audit(const JsonValue& root);
    static std::vector<ClassifierConfig> extract_classifiers(const JsonValue& root);
    static CircuitBreakerConfig extract_circuit_breaker(const JsonValue& root);
    static AllocatorConfig extract_allocator(const JsonValue& root);
    static MetricsConfig extract_metrics(const JsonValue& root);
    static ConfigWatcherConfig extract_config_watcher(const JsonValue& root);
    static SecurityConfig extract_security(const JsonValue& root);
    static EncryptionConfig extract_encryption(const JsonValue& root);

    // Tier 5 extractors
    static TenantConfigEntry extract_tenants(const JsonValue& root);
    static std::vector<PluginConfigEntry> extract_plugins(const JsonValue& root);
    static SchemaManagementConfigEntry extract_schema_management(const JsonValue& root);
    static WireProtocolConfigEntry extract_wire_protocol(const JsonValue& root);
    static GraphQLConfigEntry extract_graphql(const JsonValue& root);
    static BinaryRpcConfigEntry extract_binary_rpc(const JsonValue& root);

    // Tier 2 extractors
    static AlertingConfig extract_alerting(const JsonValue& root);

    // Tier A extractors
    static AuthConfig extract_auth(const JsonValue& root);

    // Tier B extractors
    static ProxyConfig::AuditSamplingConfig extract_audit_sampling(const JsonValue& root);
    static ProxyConfig::ResultCacheConfig extract_result_cache(const JsonValue& root);

    // Helper: parse statement type string to enum
    static std::optional<StatementType> parse_statement_type(const std::string& type_str);

    // Helper: parse action string to Decision enum
    static std::optional<Decision> parse_action(const std::string& action_str);
};

} // namespace sqlproxy
