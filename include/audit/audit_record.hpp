#pragma once

#include "core/types.hpp"

namespace sqlproxy {

// ============================================================================
// Audit Record
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
    ThreatLevel threat_level = ThreatLevel::NONE;
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

    // Per-layer tracing spans (Tier G)
    struct SpanData {
        std::string span_id;
        std::string operation;
        uint64_t duration_us = 0;
    };
    std::vector<SpanData> spans;

    // Request priority (Tier G)
    PriorityLevel priority = PriorityLevel::NORMAL;

    // Cost attribution
    double query_cost = 0.0;

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

} // namespace sqlproxy
