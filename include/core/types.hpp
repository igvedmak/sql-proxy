#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <optional>
#include <chrono>
#include <cstdint>
#include <memory>
#include "core/utils.hpp"

namespace sqlproxy {

// ============================================================================
// Basic Enums
// ============================================================================

enum class StatementType {
    UNKNOWN,
    SELECT,
    INSERT,
    UPDATE,
    DELETE,
    CREATE_TABLE,
    ALTER_TABLE,
    DROP_TABLE,
    CREATE_INDEX,
    DROP_INDEX,
    TRUNCATE,
    BEGIN,
    COMMIT,
    ROLLBACK,
    SET,
    SHOW,
    PREPARE,        // PREPARE name AS sql
    EXECUTE_STMT,   // EXECUTE name (params)
    DEALLOCATE      // DEALLOCATE name
};

// Branchless statement type classification using bitmasks.
// Each StatementType maps to a bit position; checking membership
// in a category is a single AND instruction (no branches).
namespace stmt_mask {
    inline constexpr uint32_t bit(StatementType t) noexcept {
        return static_cast<uint32_t>(1u << static_cast<int>(t));
    }
    inline constexpr uint32_t kWrite =
        bit(StatementType::INSERT) | bit(StatementType::UPDATE) | bit(StatementType::DELETE) |
        bit(StatementType::CREATE_TABLE) | bit(StatementType::ALTER_TABLE) |
        bit(StatementType::DROP_TABLE) | bit(StatementType::TRUNCATE);
    inline constexpr uint32_t kTransaction =
        bit(StatementType::BEGIN) | bit(StatementType::COMMIT) | bit(StatementType::ROLLBACK);
    inline constexpr uint32_t kDML =
        bit(StatementType::INSERT) | bit(StatementType::UPDATE) | bit(StatementType::DELETE);
    inline constexpr uint32_t kDDL =
        bit(StatementType::CREATE_TABLE) | bit(StatementType::ALTER_TABLE) |
        bit(StatementType::DROP_TABLE) | bit(StatementType::CREATE_INDEX) |
        bit(StatementType::DROP_INDEX) | bit(StatementType::TRUNCATE);
    inline constexpr uint32_t kPreparedStmt =
        bit(StatementType::PREPARE) | bit(StatementType::EXECUTE_STMT) |
        bit(StatementType::DEALLOCATE);
    [[nodiscard]] inline constexpr bool test(StatementType t, uint32_t mask) noexcept {
        return (mask & bit(t)) != 0;
    }
}

enum class Decision {
    ALLOW,
    BLOCK,
    ERROR
};

enum class ErrorCode {
    NONE,
    PARSE_ERROR,
    ACCESS_DENIED,
    RATE_LIMITED,
    CIRCUIT_OPEN,
    DATABASE_ERROR,
    INTERNAL_ERROR,
    INVALID_REQUEST,
    RESULT_TOO_LARGE,
    SQLI_BLOCKED
};

enum class ClassificationType {
    NONE,
    PII_EMAIL,
    PII_PHONE,
    PII_SSN,
    PII_CREDIT_CARD,
    SENSITIVE_SALARY,
    SENSITIVE_PASSWORD,
    CUSTOM
};

enum class MaskingAction {
    NONE,       // No masking
    REDACT,     // Replace entire value: "***REDACTED***"
    PARTIAL,    // Show prefix + "***" + suffix
    HASH,       // SHA256 first 16 hex chars
    NULLIFY     // Replace with "NULL"
};

inline const char* masking_action_to_string(MaskingAction action) {
    switch (action) {
        case MaskingAction::NONE: return "NONE";
        case MaskingAction::REDACT: return "REDACTED";
        case MaskingAction::PARTIAL: return "PARTIAL";
        case MaskingAction::HASH: return "HASH";
        case MaskingAction::NULLIFY: return "NULLIFY";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// Query Fingerprint & Cache Key
// ============================================================================

struct QueryFingerprint {
    uint64_t hash;              // xxHash64 of normalized query
    std::string normalized;     // Normalized query text (params replaced)

    QueryFingerprint() : hash(0) {}
    QueryFingerprint(uint64_t h, std::string n) : hash(h), normalized(std::move(n)) {}
};

// ============================================================================
// Parsed Query Metadata
// ============================================================================

struct TableRef {
    std::string schema;         // Schema name (empty = current schema)
    std::string table;          // Table name
    std::string alias;          // Table alias (optional)

    TableRef() = default;
    TableRef(std::string t) : table(std::move(t)) {}
    TableRef(std::string s, std::string t) : schema(std::move(s)), table(std::move(t)) {}
    TableRef(std::string s, std::string t, std::string a)
        : schema(std::move(s)), table(std::move(t)), alias(std::move(a)) {}

    std::string full_name() const {
        return schema.empty() ? table : (schema + "." + table);
    }
};

struct ColumnRef {
    std::string table;          // Table name/alias (optional)
    std::string column;         // Column name

    ColumnRef() = default;
    ColumnRef(std::string c) : column(std::move(c)) {}
    ColumnRef(std::string t, std::string c) : table(std::move(t)), column(std::move(c)) {}

    std::string full_name() const {
        return table.empty() ? column : (table + "." + column);
    }
};

struct ParsedQuery {
    StatementType type;
    std::vector<TableRef> tables;           // All referenced tables
    std::vector<ColumnRef> columns;         // SELECT columns or DML affected columns
    std::unordered_set<std::string> operations; // For complex queries: "READ", "WRITE", "DDL"

    // DDL specific
    std::optional<std::string> ddl_object_type; // "TABLE", "INDEX", etc.
    std::optional<std::string> ddl_object_name;

    // DML specific
    bool is_write;              // INSERT/UPDATE/DELETE
    bool is_transaction;        // BEGIN/COMMIT/ROLLBACK

    // Prepared statement specific
    std::string prepared_name;                      // For PREPARE/EXECUTE/DEALLOCATE
    std::vector<std::string> prepared_params;        // Bind values for EXECUTE
    std::string prepared_inner_sql;                  // SQL inside PREPARE ... AS ...

    ParsedQuery() : type(StatementType::UNKNOWN), is_write(false), is_transaction(false) {}
};

// ============================================================================
// Schema Cache Types
// ============================================================================

struct ColumnMetadata {
    std::string name;
    std::string type;           // PostgreSQL type name
    uint32_t type_oid;          // PostgreSQL OID
    bool nullable;
    bool is_primary_key;

    ColumnMetadata() : type_oid(0), nullable(true), is_primary_key(false) {}
    ColumnMetadata(std::string n, std::string t, uint32_t oid = 0,
                   bool null = true, bool pk = false)
        : name(std::move(n)), type(std::move(t)), type_oid(oid),
          nullable(null), is_primary_key(pk) {}
};

struct TableMetadata {
    std::string schema;
    std::string name;
    std::vector<ColumnMetadata> columns;
    std::unordered_map<std::string, size_t> column_index; // name -> index
    uint64_t version;           // For RCU: incremented on schema change

    TableMetadata() : version(0) {}

    const ColumnMetadata* find_column(const std::string& col_name) const {
        const auto it = column_index.find(col_name);
        if (it != column_index.end() && it->second < columns.size()) {
            return &columns[it->second];
        }
        return nullptr;
    }
};

using SchemaMap = std::unordered_map<std::string, std::shared_ptr<TableMetadata>>;

// ============================================================================
// Policy Types
// ============================================================================

struct PolicyScope {
    std::optional<std::string> database;
    std::optional<std::string> schema;
    std::optional<std::string> table;
    std::vector<std::string> columns;               // Column-level ACL (empty = all columns)
    std::unordered_set<StatementType> operations;

    // Calculate specificity: columns(1000) > table(100) > schema(10) > database(1)
    int specificity() const {
        int score = 0;
        if (!columns.empty()) score += 1000;
        if (table.has_value()) score += 100;
        if (schema.has_value()) score += 10;
        if (database.has_value()) score += 1;
        return score;
    }
};

struct Policy {
    std::string name;
    int priority;                           // Higher = evaluated first
    Decision action;                        // ALLOW or BLOCK
    PolicyScope scope;
    std::unordered_set<std::string> users;  // Empty = all users, "*" = wildcard
    std::unordered_set<std::string> roles;  // Role-based matching
    std::unordered_set<std::string> exclude_roles;  // Roles to exclude (e.g., users=["*"] exclude_roles=["admin"])
    std::string reason;                     // Human-readable explanation for audit logs

    // Masking (for column-level ALLOW policies)
    MaskingAction masking_action = MaskingAction::NONE;
    int masking_prefix_len = 3;             // For PARTIAL: chars to show at start
    int masking_suffix_len = 3;             // For PARTIAL: chars to show at end

    // Shadow mode: log decision but don't enforce
    bool shadow = false;

    Policy() : priority(0), action(Decision::BLOCK) {}

    bool matches_user(const std::string& user) const {
        return users.empty() ||
               users.contains("*") ||
               users.contains(user);
    }
};

struct PolicyEvaluationResult {
    Decision decision;
    std::string matched_policy;     // Policy name that made the decision
    std::string reason;             // Human-readable reason

    // Shadow mode: a shadow policy would have blocked, but didn't enforce
    bool shadow_blocked = false;
    std::string shadow_policy;

    PolicyEvaluationResult() : decision(Decision::BLOCK) {}
    PolicyEvaluationResult(Decision d, std::string p, std::string r)
        : decision(d), matched_policy(std::move(p)), reason(std::move(r)) {}
};

struct ColumnPolicyDecision {
    std::string column_name;
    Decision decision = Decision::ALLOW;
    MaskingAction masking = MaskingAction::NONE;
    std::string matched_policy;
    int prefix_len = 3;
    int suffix_len = 3;
};

struct MaskingRecord {
    std::string column_name;
    MaskingAction action;
    std::string matched_policy;
};

// ============================================================================
// Rate Limiter Types
// ============================================================================

struct RateLimitConfig {
    uint32_t tokens_per_second;     // Token bucket refill rate
    uint32_t burst_capacity;        // Maximum burst size

    RateLimitConfig() : tokens_per_second(0), burst_capacity(0) {}
    RateLimitConfig(uint32_t tps, uint32_t burst)
        : tokens_per_second(tps), burst_capacity(burst) {}
};

struct RateLimitResult {
    bool allowed;
    uint32_t tokens_remaining;
    std::chrono::milliseconds retry_after;
    std::string level;              // "global", "user", "database", "user_db"

    RateLimitResult() : allowed(false), tokens_remaining(0) {}

    RateLimitResult(bool a, uint32_t tr, std::chrono::milliseconds ra, std::string lv)
        : allowed(a), tokens_remaining(tr), retry_after(ra), level(std::move(lv)) {}
};

// ============================================================================
// Circuit Breaker Types
// ============================================================================

enum class CircuitState {
    CLOSED,         // Normal operation
    OPEN,           // Failing, reject requests
    HALF_OPEN       // Testing recovery
};

struct CircuitBreakerStats {
    CircuitState state;
    uint64_t success_count;
    uint64_t failure_count;
    std::chrono::system_clock::time_point last_failure;
    std::chrono::system_clock::time_point opened_at;

    CircuitBreakerStats()
        : state(CircuitState::CLOSED), success_count(0), failure_count(0) {}
};

// ============================================================================
// Query Execution Types
// ============================================================================

struct QueryResult {
    bool success;
    ErrorCode error_code;
    std::string error_message;

    // For SELECT
    std::vector<std::string> column_names;
    std::vector<uint32_t> column_type_oids;  // PostgreSQL type OIDs for classification
    std::vector<std::vector<std::string>> rows;

    // For DML
    uint64_t affected_rows;

    // Performance metrics
    std::chrono::microseconds execution_time;

    QueryResult()
        : success(false),
          error_code(ErrorCode::NONE),
          affected_rows(0),
          execution_time(0) {}
};

// ============================================================================
// Classification Types
// ============================================================================

struct ColumnClassification {
    std::string column_name;
    ClassificationType type;
    std::string custom_label;       // For CUSTOM type
    double confidence;              // 0.0 - 1.0
    std::string strategy;           // Which strategy detected it

    ColumnClassification()
        : type(ClassificationType::NONE), confidence(0.0) {}
    ColumnClassification(std::string col, ClassificationType t,
                         double conf, std::string strat, std::string custom = "")
        : column_name(std::move(col)), type(t), custom_label(std::move(custom)),
          confidence(conf), strategy(std::move(strat)) {}

    std::string type_string() const {
        switch (type) {
            case ClassificationType::PII_EMAIL: return "PII.Email";
            case ClassificationType::PII_PHONE: return "PII.Phone";
            case ClassificationType::PII_SSN: return "PII.SSN";
            case ClassificationType::PII_CREDIT_CARD: return "PII.CreditCard";
            case ClassificationType::SENSITIVE_SALARY: return "Sensitive.Salary";
            case ClassificationType::SENSITIVE_PASSWORD: return "Sensitive.Password";
            case ClassificationType::CUSTOM: return custom_label;
            default: return "None";
        }
    }
};

struct ClassificationResult {
    std::unordered_map<std::string, ColumnClassification> classifications;
    std::chrono::microseconds processing_time;

    ClassificationResult() : processing_time(0) {}

    std::vector<std::string> get_classified_types() const {
        std::vector<std::string> types;
        for (const auto& [col, cls] : classifications) {
            if (cls.type != ClassificationType::NONE) {
                types.push_back(cls.type_string());
            }
        }
        return types;
    }
};

// ============================================================================
// Audit Types
// ============================================================================

struct AuditRecord {
    std::string audit_id;               // UUID (v7 for time-sortable)
    uint64_t sequence_num;              // Monotonic counter for gap detection
    std::chrono::system_clock::time_point timestamp;
    std::chrono::system_clock::time_point received_at;  // Request arrival time

    // Request context
    std::string user;
    std::string source_ip;
    std::string session_id;

    // Query info
    std::string sql;
    QueryFingerprint fingerprint;
    StatementType statement_type;
    std::vector<std::string> tables;
    std::vector<std::string> columns;
    std::vector<std::string> columns_filtered;  // WHERE/JOIN columns for intent analysis

    // Policy decision
    Decision decision;
    std::string matched_policy;
    std::string block_reason;
    int32_t rule_specificity;           // Policy specificity score for dead rule detection

    // Execution results
    bool execution_attempted;
    bool execution_success;
    ErrorCode error_code;
    std::string error_message;
    uint64_t rows_affected;
    uint64_t rows_returned;

    // Classification
    std::vector<std::string> detected_classifications;

    // Performance
    std::chrono::microseconds total_duration;
    std::chrono::microseconds parse_time;
    std::chrono::microseconds policy_time;
    std::chrono::microseconds execution_time;
    std::chrono::microseconds classification_time;
    std::chrono::microseconds proxy_overhead;   // total_duration - execution_time

    // Rate limiting
    bool rate_limited;
    std::string rate_limit_level;

    // Circuit breaker
    bool circuit_breaker_tripped;
    std::string database_name;

    // Cache
    bool cache_hit;                     // Parse cache hit for operational monitoring

    // Distributed tracing (W3C Trace Context)
    std::string trace_id;               // 32 hex chars (128-bit)
    std::string span_id;                // 16 hex chars (64-bit)
    std::string parent_span_id;         // 16 hex chars (64-bit)

    // Masking / query rewriting
    std::vector<std::string> masked_columns;
    bool sql_rewritten = false;
    std::string original_sql;

    // Security detection
    std::string threat_level;
    std::vector<std::string> injection_patterns;
    bool injection_blocked = false;
    double anomaly_score = 0.0;
    std::vector<std::string> anomalies;

    // Integrity (hash chain)
    std::string record_hash;        // SHA-256 of this record's content
    std::string previous_hash;      // Hash of previous record (chain link)

    // Shadow mode
    bool shadow_blocked = false;
    std::string shadow_policy;

    AuditRecord()
        : audit_id(utils::generate_uuid()),
          sequence_num(0),
          statement_type(StatementType::UNKNOWN),
          decision(Decision::BLOCK),
          rule_specificity(0),
          execution_attempted(false),
          execution_success(false),
          error_code(ErrorCode::NONE),
          rows_affected(0),
          rows_returned(0),
          total_duration(0),
          parse_time(0),
          policy_time(0),
          execution_time(0),
          classification_time(0),
          proxy_overhead(0),
          rate_limited(false),
          circuit_breaker_tripped(false),
          cache_hit(false) {}
};

// ============================================================================
// Request/Response Types
// ============================================================================

struct ProxyRequest {
    std::string request_id;         // Generated UUID
    std::string user;
    std::vector<std::string> roles; // User roles (for policy evaluation)
    std::string sql;
    std::string source_ip;
    std::string session_id;
    std::string database;           // Target database
    std::unordered_map<std::string, std::string> user_attributes; // For RLS template expansion
    std::string tenant_id;          // Multi-tenant routing (Tier 5)
    std::string traceparent;        // W3C traceparent header (incoming)
    std::string tracestate;         // W3C tracestate header (propagated as-is)
    std::chrono::system_clock::time_point received_at;
    bool dry_run = false;           // Dry-run mode: evaluate but don't execute

    ProxyRequest()
        : request_id(utils::generate_uuid()),
          received_at(std::chrono::system_clock::now()) {}
};

struct ProxyResponse {
    std::string request_id;
    std::string audit_id;
    bool success;
    ErrorCode error_code;
    std::string error_message;

    // Query result
    std::optional<QueryResult> result;

    // Classifications
    std::unordered_map<std::string, std::string> classifications;

    // Performance metrics
    std::chrono::microseconds execution_time_ms;

    // Metadata
    Decision policy_decision;
    std::string matched_policy;

    // Column-level masking metadata
    std::vector<std::string> masked_columns;
    std::vector<std::string> blocked_columns;

    // Shadow mode
    bool shadow_blocked = false;
    std::string shadow_policy;

    // Distributed tracing
    std::string traceparent;        // W3C traceparent header (outgoing)

    ProxyResponse()
        : audit_id(utils::generate_uuid()),
          success(false),
          error_code(ErrorCode::NONE),
          execution_time_ms(0),
          policy_decision(Decision::BLOCK) {}
};

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
// Row-Level Security & Query Rewriting Config
// ============================================================================

struct RlsRule {
    std::string name;
    std::optional<std::string> database;
    std::optional<std::string> table;
    std::string condition;                  // SQL with $USER, $ROLES, $ATTR.key
    std::vector<std::string> users;
    std::vector<std::string> roles;
};

struct RewriteRule {
    std::string name;
    std::string type;                       // "enforce_limit"
    int limit_value = 1000;
    std::vector<std::string> users;
    std::vector<std::string> roles;
};

// ============================================================================
// Utility Functions
// ============================================================================

inline const char* statement_type_to_string(StatementType type) {
    switch (type) {
        case StatementType::SELECT: return "SELECT";
        case StatementType::INSERT: return "INSERT";
        case StatementType::UPDATE: return "UPDATE";
        case StatementType::DELETE: return "DELETE";
        case StatementType::CREATE_TABLE: return "CREATE_TABLE";
        case StatementType::ALTER_TABLE: return "ALTER_TABLE";
        case StatementType::DROP_TABLE: return "DROP_TABLE";
        case StatementType::CREATE_INDEX: return "CREATE_INDEX";
        case StatementType::DROP_INDEX: return "DROP_INDEX";
        case StatementType::TRUNCATE: return "TRUNCATE";
        case StatementType::BEGIN: return "BEGIN";
        case StatementType::COMMIT: return "COMMIT";
        case StatementType::ROLLBACK: return "ROLLBACK";
        case StatementType::SET: return "SET";
        case StatementType::SHOW: return "SHOW";
        case StatementType::PREPARE: return "PREPARE";
        case StatementType::EXECUTE_STMT: return "EXECUTE";
        case StatementType::DEALLOCATE: return "DEALLOCATE";
        default: return "UNKNOWN";
    }
}

inline const char* decision_to_string(Decision decision) {
    switch (decision) {
        case Decision::ALLOW: return "ALLOW";
        case Decision::BLOCK: return "BLOCK";
        case Decision::ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

inline const char* error_code_to_string(ErrorCode code) {
    switch (code) {
        case ErrorCode::NONE: return "NONE";
        case ErrorCode::PARSE_ERROR: return "PARSE_ERROR";
        case ErrorCode::ACCESS_DENIED: return "ACCESS_DENIED";
        case ErrorCode::RATE_LIMITED: return "RATE_LIMITED";
        case ErrorCode::CIRCUIT_OPEN: return "CIRCUIT_OPEN";
        case ErrorCode::DATABASE_ERROR: return "DATABASE_ERROR";
        case ErrorCode::INTERNAL_ERROR: return "INTERNAL_ERROR";
        case ErrorCode::INVALID_REQUEST: return "INVALID_REQUEST";
        case ErrorCode::RESULT_TOO_LARGE: return "RESULT_TOO_LARGE";
        case ErrorCode::SQLI_BLOCKED: return "SQLI_BLOCKED";
        default: return "UNKNOWN";
    }
}

} // namespace sqlproxy
