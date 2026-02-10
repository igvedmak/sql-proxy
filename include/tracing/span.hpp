#pragma once

#include <chrono>
#include <string>
#include <vector>

namespace sqlproxy {

// Forward declaration
struct TraceContext;
struct RequestContext;

/**
 * @brief Represents a single span in the pipeline execution
 *
 * Each pipeline layer gets its own span with timing information.
 * Spans are collected in RequestContext::spans and serialized to audit records.
 */
struct Span {
    std::string span_id;        // 16 hex chars (unique per span)
    std::string parent_span_id; // Request-level span ID
    std::string operation;      // e.g. "sql_proxy.parse", "sql_proxy.policy"
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;

    /// Duration in microseconds
    [[nodiscard]] uint64_t duration_us() const {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                end_time - start_time).count());
    }
};

/**
 * @brief Simplified span data for audit record serialization
 */
struct SpanData {
    std::string span_id;
    std::string operation;
    uint64_t duration_us = 0;
};

/**
 * @brief RAII span helper — creates span on construction, finishes on destruction
 *
 * Usage:
 *   void Pipeline::parse_query(RequestContext& ctx) {
 *       ScopedSpan span(ctx, "sql_proxy.parse");
 *       // ... parsing logic ...
 *   } // span automatically recorded on scope exit
 */
class ScopedSpan {
public:
    ScopedSpan(RequestContext& ctx, const char* operation);
    ~ScopedSpan();

    ScopedSpan(const ScopedSpan&) = delete;
    ScopedSpan& operator=(const ScopedSpan&) = delete;

private:
    RequestContext& ctx_;
    Span span_;
};

} // namespace sqlproxy
