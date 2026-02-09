#pragma once

#include "core/types.hpp"
#include "core/arena.hpp"
#include "core/utils.hpp"
#include "parser/fingerprinter.hpp"
#include "parser/parse_cache.hpp"
#include "analyzer/sql_analyzer.hpp"
#include "security/sql_injection_detector.hpp"
#include "security/anomaly_detector.hpp"
#include "tracing/trace_context.hpp"
#include <memory>
#include <chrono>

namespace sqlproxy {

/**
 * @brief Request context - carries state through pipeline
 *
 * Allocated from arena, flows through all 7 layers.
 * Contains input, intermediate results, and final output.
 */
struct RequestContext {
    // Input
    std::string request_id;
    std::string user;
    std::vector<std::string> roles;
    std::string database;
    std::string sql;
    std::string source_ip;

    // Timestamps
    std::chrono::system_clock::time_point received_at;
    std::chrono::steady_clock::time_point started_at;

    // Per-request memory arena
    Arena arena;

    // Pipeline stage results
    std::optional<QueryFingerprint> fingerprint;
    std::shared_ptr<StatementInfo> statement_info;
    AnalysisResult analysis;
    PolicyEvaluationResult policy_result;
    QueryResult query_result;
    ClassificationResult classification_result;

    // Timing breakdown
    std::chrono::microseconds parse_time{0};
    std::chrono::microseconds policy_time{0};
    std::chrono::microseconds execution_time{0};
    std::chrono::microseconds classification_time{0};

    // Flags
    bool cache_hit = false;
    bool rate_limited = false;
    bool circuit_breaker_open = false;
    RateLimitResult rate_limit_result;  // Full result for response headers

    // Column policy + masking
    std::vector<ColumnPolicyDecision> column_decisions;
    std::vector<MaskingRecord> masking_applied;
    std::chrono::microseconds masking_time{0};
    std::chrono::microseconds column_policy_time{0};

    // Query rewriting
    std::string original_sql;
    bool sql_rewritten = false;

    // User attributes (for RLS template expansion)
    std::unordered_map<std::string, std::string> user_attributes;

    // Security detection
    SqlInjectionDetector::DetectionResult injection_result;
    std::chrono::microseconds injection_check_time{0};
    AnomalyDetector::AnomalyResult anomaly_result;

    // Distributed tracing (W3C Trace Context)
    TraceContext trace_context;

    // Tenant (Tier 5)
    std::string tenant_id;

    // Schema management (Tier 5)
    bool ddl_requires_approval = false;

    // Dry-run mode (evaluate policy but skip execution)
    bool dry_run = false;

    RequestContext()
        : request_id(utils::generate_uuid()),
          received_at(std::chrono::system_clock::now()),
          started_at(std::chrono::steady_clock::now()),
          arena(1024) {}
};

} // namespace sqlproxy
