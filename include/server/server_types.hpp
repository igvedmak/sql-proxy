#pragma once

#include "core/types.hpp"

namespace sqlproxy {

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
    PriorityLevel priority = PriorityLevel::NORMAL;

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

    // Rate limit info for response headers
    RateLimitResult rate_limit_info;

    ProxyResponse()
        : audit_id(utils::generate_uuid()),
          success(false),
          error_code(ErrorCode::NONE),
          execution_time_ms(0),
          policy_decision(Decision::BLOCK) {}
};

} // namespace sqlproxy
