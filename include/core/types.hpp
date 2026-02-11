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
#include "server/request_priority.hpp"

namespace sqlproxy {

// ============================================================================
// Security Enums
// ============================================================================

enum class ThreatLevel : uint8_t { NONE, LOW, MEDIUM, HIGH, CRITICAL };

inline const char* threat_level_to_string(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::NONE:     return "NONE";
        case ThreatLevel::LOW:      return "LOW";
        case ThreatLevel::MEDIUM:   return "MEDIUM";
        case ThreatLevel::HIGH:     return "HIGH";
        case ThreatLevel::CRITICAL: return "CRITICAL";
        default:                    return "NONE";
    }
}

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
    DEALLOCATE,     // DEALLOCATE name
    COPY            // COPY ... FROM/TO
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
    SQLI_BLOCKED,
    QUERY_TIMEOUT,
    QUERY_TOO_EXPENSIVE,
    FIREWALL_BLOCKED,
    RESIDENCY_BLOCKED,
    COPY_NOT_SUPPORTED
};

enum class FailureCategory {
    INFRASTRUCTURE,  // Connection refused, timeout, host unreachable
    APPLICATION,     // Syntax error, constraint violation, permission denied
    TRANSIENT        // Deadlock, lock timeout (may be retried)
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
    uint64_t infrastructure_failure_count;
    uint64_t application_failure_count;
    uint64_t transient_failure_count;
    std::chrono::system_clock::time_point last_failure;
    std::chrono::system_clock::time_point opened_at;

    CircuitBreakerStats()
        : state(CircuitState::CLOSED), success_count(0), failure_count(0),
          infrastructure_failure_count(0), application_failure_count(0),
          transient_failure_count(0) {}
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
        case StatementType::COPY: return "COPY";
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
        case ErrorCode::QUERY_TIMEOUT: return "QUERY_TIMEOUT";
        case ErrorCode::QUERY_TOO_EXPENSIVE: return "QUERY_TOO_EXPENSIVE";
        case ErrorCode::FIREWALL_BLOCKED: return "FIREWALL_BLOCKED";
        case ErrorCode::RESIDENCY_BLOCKED: return "RESIDENCY_BLOCKED";
        case ErrorCode::COPY_NOT_SUPPORTED: return "COPY_NOT_SUPPORTED";
        default: return "UNKNOWN";
    }
}

} // namespace sqlproxy

// ============================================================================
// Domain-specific type files (backward compatibility: including types.hpp
// still provides all types; individual files can be included directly)
// ============================================================================
#include "policy/policy_types.hpp"
#include "audit/audit_record.hpp"
#include "server/server_types.hpp"
#include "config/config_types.hpp"
