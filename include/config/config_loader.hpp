#pragma once

#include "core/types.hpp"
#include "server/http_server.hpp"  // UserInfo
#include "alerting/alert_types.hpp"
#include "config/config_types.hpp"

#include <toml.hpp>

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

    // SQL Firewall
    bool firewall_enabled = false;
    std::string firewall_mode = "disabled";

    // Brute force protection
    bool brute_force_enabled = false;
    uint32_t brute_force_max_attempts = 5;
    uint32_t brute_force_window_seconds = 60;
    uint32_t brute_force_lockout_seconds = 300;
    uint32_t brute_force_max_lockout_seconds = 3600;
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
    std::string provider = "api_key";  // "api_key" | "jwt" | "ldap" | "oidc"
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
    // OIDC
    std::string oidc_issuer;
    std::string oidc_audience;
    std::string oidc_jwks_uri;
    std::string oidc_roles_claim = "roles";
    std::string oidc_user_claim = "sub";
    uint32_t oidc_jwks_cache_seconds = 3600;
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

    // SCRAM-SHA-256 authentication
    bool prefer_scram = false;
    uint32_t scram_iterations = 4096;

    // TLS
    struct Tls {
        bool enabled = false;
        std::string cert_file;
        std::string key_file;
        std::string ca_file;
        bool require_client_cert = false;
    } tls;
};

struct GraphQLConfigEntry {
    bool enabled = false;
    std::string endpoint = "/api/v1/graphql";
    uint32_t max_query_depth = 5;
    bool mutations_enabled = false;
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

    // Tier C (Roadmap features)
    struct SlowQueryConfig {
        bool enabled = false;
        uint32_t threshold_ms = 500;
        size_t max_entries = 1000;
    } slow_query;

    // Tier F (P1/P2 Roadmap features)
    struct QueryCostConfig {
        bool enabled = false;
        double max_cost = 100000.0;
        uint64_t max_estimated_rows = 1000000;
        bool log_estimates = false;
    } query_cost;

    struct SchemaDriftConfig {
        bool enabled = false;
        int check_interval_seconds = 600;
        std::string database = "testdb";
        std::string schema_name = "public";
    } schema_drift;

    struct RetryConfig {
        bool enabled = false;
        int max_retries = 1;
        int initial_backoff_ms = 100;
        int max_backoff_ms = 2000;
    } retry;

    struct RequestTimeoutConfig {
        bool enabled = true;
        uint32_t timeout_ms = 30000;
    } request_timeout;

    // Tier G (Audit encryption, tracing, adaptive rate limiting, priority)
    struct AuditEncryptionConfig {
        bool enabled = false;
        std::string key_id = "audit-key-1";
    } audit_encryption;

    struct TracingConfig {
        bool spans_enabled = false;
    } tracing;

    struct AdaptiveRateLimitingConfig {
        bool enabled = false;
        uint32_t adjustment_interval_seconds = 10;
        uint32_t latency_target_ms = 50;
        uint32_t throttle_threshold_ms = 200;
    } adaptive_rate_limiting;

    struct PriorityConfig {
        bool enabled = false;
    } priority;

    // Data Residency
    struct DataResidencyConfig {
        bool enabled = false;
    } data_residency;

    // Column Versioning
    struct ColumnVersioningConfig {
        bool enabled = false;
        size_t max_events = 10000;
    } column_versioning;

    // Synthetic Data
    struct SyntheticDataConfig {
        bool enabled = false;
        size_t max_rows = 10000;
    } synthetic_data;

    // Cost-Based Query Rewriting
    struct CostBasedRewritingConfig {
        bool enabled = false;
        double cost_threshold = 50000.0;
        size_t max_columns_for_star = 20;
    } cost_based_rewriting;

    // Distributed Rate Limiting
    struct DistributedRateLimitingConfig {
        bool enabled = false;
        std::string node_id = "node-1";
        uint32_t cluster_size = 1;
        uint32_t sync_interval_ms = 5000;
        std::string backend_type = "memory";
    } distributed_rate_limiting;

    // WebSocket Streaming
    struct WebSocketConfig {
        bool enabled = false;
        std::string endpoint = "/api/v1/stream";
        uint32_t max_connections = 100;
        uint32_t ping_interval_seconds = 30;
        size_t max_frame_size = 65536;
    } websocket;

    // Multi-Database Transactions
    struct TransactionConfig {
        bool enabled = false;
        uint32_t timeout_ms = 30000;
        uint32_t max_active_transactions = 100;
        uint32_t cleanup_interval_seconds = 60;
    } transactions;

    // LLM Features
    struct LlmConfig {
        bool enabled = false;
        std::string provider = "openai";  // "openai" or "anthropic"
        std::string endpoint = "https://api.openai.com";
        std::string api_key;
        std::string default_model = "gpt-4";
        uint32_t timeout_ms = 30000;
        uint32_t max_retries = 2;
        uint32_t max_requests_per_minute = 60;
        bool cache_enabled = true;
        size_t cache_max_entries = 1000;
        uint32_t cache_ttl_seconds = 3600;
    } llm;

    // Route paths (config-driven URL patterns)
    RouteConfig routes;

    // Feature toggles (for features that lack their own [section].enabled)
    bool classification_enabled = true;
    bool masking_enabled = true;
    bool openapi_enabled = true;
    bool dry_run_enabled = true;
    bool data_catalog_enabled = false;
    bool policy_simulator_enabled = false;
};

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
            return {.success = true, .error_message = {}, .config = std::move(cfg)};
        }

        static LoadResult error(std::string message) {
            return {.success = false, .error_message = std::move(message), .config = {}};
        }
    };

    [[nodiscard]] static LoadResult load_from_file(const std::string& config_path);
    [[nodiscard]] static LoadResult load_from_string(const std::string& toml_content);

private:
    static ServerConfig extract_server(const toml::table& root);
    static LoggingConfig extract_logging(const toml::table& root);
    static std::vector<DatabaseConfig> extract_databases(const toml::table& root);
    static std::unordered_map<std::string, UserInfo> extract_users(const toml::table& root);
    static std::vector<Policy> extract_policies(const toml::table& root);
    static RateLimitingConfig extract_rate_limiting(const toml::table& root);
    static CacheConfig extract_cache(const toml::table& root);
    static AuditConfig extract_audit(const toml::table& root);
    static std::vector<ClassifierConfig> extract_classifiers(const toml::table& root);
    static CircuitBreakerConfig extract_circuit_breaker(const toml::table& root);
    static AllocatorConfig extract_allocator(const toml::table& root);
    static MetricsConfig extract_metrics(const toml::table& root);
    static ConfigWatcherConfig extract_config_watcher(const toml::table& root);
    static SecurityConfig extract_security(const toml::table& root);
    static EncryptionConfig extract_encryption(const toml::table& root);

    // Tier 5 extractors
    static TenantConfigEntry extract_tenants(const toml::table& root);
    static std::vector<PluginConfigEntry> extract_plugins(const toml::table& root);
    static SchemaManagementConfigEntry extract_schema_management(const toml::table& root);
    static WireProtocolConfigEntry extract_wire_protocol(const toml::table& root);
    static GraphQLConfigEntry extract_graphql(const toml::table& root);
    static BinaryRpcConfigEntry extract_binary_rpc(const toml::table& root);

    // Tier 2 extractors
    static AlertingConfig extract_alerting(const toml::table& root);

    // Tier A extractors
    static AuthConfig extract_auth(const toml::table& root);

    // Tier B extractors
    static ProxyConfig::AuditSamplingConfig extract_audit_sampling(const toml::table& root);
    static ProxyConfig::ResultCacheConfig extract_result_cache(const toml::table& root);

    // Tier C extractors
    static ProxyConfig::SlowQueryConfig extract_slow_query(const toml::table& root);

    // Tier F extractors
    static ProxyConfig::QueryCostConfig extract_query_cost(const toml::table& root);
    static ProxyConfig::SchemaDriftConfig extract_schema_drift(const toml::table& root);
    static ProxyConfig::RetryConfig extract_retry(const toml::table& root);
    static ProxyConfig::RequestTimeoutConfig extract_request_timeout(const toml::table& root);

    // Tier G extractors
    static ProxyConfig::AuditEncryptionConfig extract_audit_encryption(const toml::table& root);
    static ProxyConfig::TracingConfig extract_tracing(const toml::table& root);
    static ProxyConfig::AdaptiveRateLimitingConfig extract_adaptive_rate_limiting(const toml::table& root);
    static ProxyConfig::PriorityConfig extract_priority(const toml::table& root);

    // New feature extractors
    static ProxyConfig::DataResidencyConfig extract_data_residency(const toml::table& root);
    static ProxyConfig::ColumnVersioningConfig extract_column_versioning(const toml::table& root);
    static ProxyConfig::SyntheticDataConfig extract_synthetic_data(const toml::table& root);
    static ProxyConfig::CostBasedRewritingConfig extract_cost_based_rewriting(const toml::table& root);
    static ProxyConfig::DistributedRateLimitingConfig extract_distributed_rate_limiting(const toml::table& root);
    static ProxyConfig::WebSocketConfig extract_websocket(const toml::table& root);
    static ProxyConfig::TransactionConfig extract_transactions(const toml::table& root);
    static ProxyConfig::LlmConfig extract_llm(const toml::table& root);

    // Route config extractor
    static RouteConfig extract_routes(const toml::table& root);

    // Feature flags extractor
    static void extract_features(const toml::table& root, ProxyConfig& config);

    // Helper: parse statement type string to enum
    static std::optional<StatementType> parse_statement_type(const std::string& type_str);

    // Helper: parse action string to Decision enum
    static std::optional<Decision> parse_action(const std::string& action_str);

    // Shared extraction + validation
    [[nodiscard]] static ProxyConfig extract_all_sections(const toml::table& root);
    [[nodiscard]] static LoadResult validate_and_return(ProxyConfig config);

    // Semantic validation (called after parsing)
    [[nodiscard]] static std::vector<std::string> validate_config(const ProxyConfig& config);
};

} // namespace sqlproxy
