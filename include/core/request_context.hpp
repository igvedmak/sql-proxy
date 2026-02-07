#pragma once

#include "core/types.hpp"
#include "core/arena.hpp"
#include "parser/fingerprinter.hpp"
#include "parser/parse_cache.hpp"
#include "analyzer/sql_analyzer.hpp"
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

    RequestContext()
        : received_at(std::chrono::system_clock::now()),
          started_at(std::chrono::steady_clock::now()),
          arena(1024) {}
};

} // namespace sqlproxy
