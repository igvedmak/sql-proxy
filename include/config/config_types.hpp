#pragma once

#include <string>
#include <vector>
#include <optional>
#include <chrono>
#include <cstdint>

namespace sqlproxy {

// ============================================================================
// Configuration Types
// ============================================================================

struct TlsConfig {
    bool enabled = false;
    std::string cert_file;            // Server certificate (PEM)
    std::string key_file;             // Server private key (PEM)
    std::string ca_file;              // CA cert for client verification (mTLS)
    bool require_client_cert = false; // mTLS mode
};

struct ServerConfig {
    std::string host;
    uint16_t port;
    size_t thread_pool_size;
    std::chrono::milliseconds request_timeout;
    std::string admin_token;  // Bearer token for admin endpoints (empty = no auth)
    size_t max_sql_length;    // Max SQL query size in bytes
    TlsConfig tls;            // TLS/mTLS configuration
    uint32_t shutdown_timeout_ms = 30000;  // Graceful shutdown timeout
    bool compression_enabled = false;
    size_t compression_min_size_bytes = 1024;

    ServerConfig()
        : host("0.0.0.0"),
          port(8080),
          thread_pool_size(4),
          request_timeout(30000),
          max_sql_length(102400) {}  // 100KB
};

struct ReplicaConfig {
    std::string connection_string;
    size_t min_connections = 2;
    size_t max_connections = 5;
    std::chrono::milliseconds connection_timeout{5000};
    std::string health_check_query{"SELECT 1"};
    int weight = 1;
};

struct DatabaseConfig {
    std::string name;
    std::string type_str = "postgresql";  // Database type string (parsed at use site)
    std::string connection_string;
    size_t min_connections;
    size_t max_connections;
    std::chrono::milliseconds connection_timeout;
    std::chrono::milliseconds query_timeout;
    std::string health_check_query;
    int health_check_interval_seconds;
    int idle_timeout_seconds;
    int pool_acquire_timeout_ms;
    size_t max_result_rows;
    std::vector<ReplicaConfig> replicas;  // Read replicas for read/write splitting

    DatabaseConfig()
        : name("default"),
          min_connections(2),
          max_connections(10),
          connection_timeout(5000),
          query_timeout(30000),
          health_check_query("SELECT 1"),
          health_check_interval_seconds(10),
          idle_timeout_seconds(300),
          pool_acquire_timeout_ms(5000),
          max_result_rows(10000) {}
};

struct CacheConfig {
    size_t max_entries;
    size_t num_shards;
    std::chrono::seconds ttl;

    CacheConfig()
        : max_entries(10000),
          num_shards(16),
          ttl(300) {}
};

struct AuditConfig {
    std::string output_file;
    size_t ring_buffer_size;
    std::chrono::milliseconds batch_flush_interval;
    bool async_mode;
    size_t max_batch_size;
    int fsync_interval_batches;

    // File rotation
    size_t rotation_max_file_size_mb = 100;
    int rotation_max_files = 10;
    int rotation_interval_hours = 24;
    bool rotation_time_based = true;
    bool rotation_size_based = true;

    // Webhook sink
    bool webhook_enabled = false;
    std::string webhook_url;
    std::string webhook_auth_header;
    int webhook_timeout_ms = 5000;
    int webhook_max_retries = 3;
    int webhook_batch_size = 100;

    // Syslog sink
    bool syslog_enabled = false;
    std::string syslog_ident = "sql-proxy";

    // Kafka sink
    bool kafka_enabled = false;
    std::string kafka_brokers = "localhost:9092";
    std::string kafka_topic = "sql-proxy-audit";

    // Integrity (hash chain)
    bool integrity_enabled = true;
    std::string integrity_algorithm = "sha256";

    AuditConfig()
        : output_file("audit.jsonl"),
          ring_buffer_size(65536),
          batch_flush_interval(1000),
          async_mode(true),
          max_batch_size(1000),
          fsync_interval_batches(10) {}
};

// ============================================================================
// Route Configuration (config-driven URL patterns)
// ============================================================================

struct RouteConfig {
    // Core
    std::string query           = "/api/v1/query";
    std::string dry_run         = "/api/v1/query/dry-run";
    std::string health          = "/health";
    std::string metrics         = "/metrics";
    std::string openapi_spec    = "/openapi.json";
    std::string swagger_ui      = "/api/docs";

    // Admin
    std::string policies_reload = "/policies/reload";
    std::string config_validate = "/api/v1/config/validate";
    std::string slow_queries    = "/api/v1/slow-queries";
    std::string circuit_breakers = "/api/v1/circuit-breakers";
    std::string plugin_reload   = "/api/v1/plugins/reload";

    // Compliance
    std::string pii_report          = "/api/v1/compliance/pii-report";
    std::string security_summary    = "/api/v1/compliance/security-summary";
    std::string lineage             = "/api/v1/compliance/lineage";
    std::string data_subject_access = "/api/v1/compliance/data-subject-access";

    // Schema
    std::string schema_history  = "/api/v1/schema/history";
    std::string schema_pending  = "/api/v1/schema/pending";
    std::string schema_approve  = "/api/v1/schema/approve";
    std::string schema_reject   = "/api/v1/schema/reject";
    std::string schema_drift    = "/api/v1/schema/drift";

    // Firewall
    std::string firewall_mode      = "/api/v1/firewall/mode";
    std::string firewall_allowlist = "/api/v1/firewall/allowlist";

    // Tenant provisioning
    std::string tenants            = "/admin/tenants";

    // Query explanation
    std::string query_explain      = "/api/v1/query/explain";

    // Index recommendations
    std::string index_recommendations = "/api/v1/index-recommendations";

    // Optional
    std::string graphql         = "/api/v1/graphql";

    // Dashboard
    std::string dashboard           = "/dashboard";
    std::string dashboard_stats     = "/dashboard/api/stats";
    std::string dashboard_policies  = "/dashboard/api/policies";
    std::string dashboard_users     = "/dashboard/api/users";
    std::string dashboard_alerts    = "/dashboard/api/alerts";
    std::string dashboard_stream    = "/dashboard/api/metrics/stream";
};

// ============================================================================
// Feature Flags (aggregated enable/disable for route gating)
// ============================================================================

struct FeatureFlags {
    bool dry_run = true;
    bool openapi = true;
    bool swagger_ui = true;
    bool metrics = true;
    bool slow_query = false;
    bool schema_drift = false;
    bool classification = true;
    bool injection_detection = true;
    bool lineage_tracking = true;
    bool masking = true;
    bool dashboard = true;
    bool sql_firewall = false;
};

} // namespace sqlproxy
