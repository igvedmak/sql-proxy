#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace sqlproxy {

/**
 * @brief W3C Trace Context (traceparent + tracestate)
 *
 * Implements parsing and generation of W3C Trace Context headers
 * for distributed tracing. No OpenTelemetry dependency — just header
 * parsing and random ID generation.
 *
 * Format: "00-{trace_id}-{parent_id}-{flags}"
 *   trace_id: 32 hex chars (128-bit)
 *   parent_id: 16 hex chars (64-bit)
 *   flags: 2 hex chars (8-bit, 01 = sampled)
 */
struct TraceContext {
    std::string trace_id;       // 32 hex chars (128-bit)
    std::string parent_span_id; // 16 hex chars (64-bit), from incoming traceparent
    std::string span_id;        // 16 hex chars (64-bit), generated per-request
    uint8_t trace_flags = 1;    // 01 = sampled by default
    std::string tracestate;     // Opaque vendor-specific state (propagated as-is)

    [[nodiscard]] bool is_valid() const;
    [[nodiscard]] bool is_sampled() const { return (trace_flags & 0x01) != 0; }

    /// Generate a fresh trace context (new trace_id + span_id)
    [[nodiscard]] static TraceContext generate();

    /// Parse W3C traceparent header: "00-{trace_id}-{parent_id}-{flags}"
    [[nodiscard]] static std::optional<TraceContext> parse_traceparent(std::string_view header);

    /// Serialize to traceparent header value
    [[nodiscard]] std::string to_traceparent() const;

    /// Generate a random 16-hex-char span ID
    [[nodiscard]] static std::string generate_span_id();

    /// Generate a random 32-hex-char trace ID
    [[nodiscard]] static std::string generate_trace_id();
};

} // namespace sqlproxy
