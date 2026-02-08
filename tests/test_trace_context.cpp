#include <catch2/catch_test_macros.hpp>
#include "tracing/trace_context.hpp"

using namespace sqlproxy;

// ============================================================================
// W3C Trace Context Tests
// ============================================================================

TEST_CASE("TraceContext: parse valid traceparent", "[tracing]") {
    auto ctx = TraceContext::parse_traceparent(
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");

    REQUIRE(ctx.has_value());
    REQUIRE(ctx->trace_id == "4bf92f3577b34da6a3ce929d0e0e4736");
    REQUIRE(ctx->parent_span_id == "00f067aa0ba902b7");
    REQUIRE(ctx->trace_flags == 0x01);
    REQUIRE(ctx->is_sampled());
    REQUIRE(ctx->span_id.size() == 16); // Generated new span
}

TEST_CASE("TraceContext: parse unsampled traceparent", "[tracing]") {
    auto ctx = TraceContext::parse_traceparent(
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00");

    REQUIRE(ctx.has_value());
    REQUIRE(ctx->trace_flags == 0x00);
    REQUIRE_FALSE(ctx->is_sampled());
}

TEST_CASE("TraceContext: reject invalid version", "[tracing]") {
    auto ctx = TraceContext::parse_traceparent(
        "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
    REQUIRE_FALSE(ctx.has_value());
}

TEST_CASE("TraceContext: reject too short header", "[tracing]") {
    auto ctx = TraceContext::parse_traceparent("00-abcd-1234-01");
    REQUIRE_FALSE(ctx.has_value());
}

TEST_CASE("TraceContext: reject all-zero trace_id", "[tracing]") {
    auto ctx = TraceContext::parse_traceparent(
        "00-00000000000000000000000000000000-00f067aa0ba902b7-01");
    REQUIRE_FALSE(ctx.has_value());
}

TEST_CASE("TraceContext: reject all-zero parent_id", "[tracing]") {
    auto ctx = TraceContext::parse_traceparent(
        "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01");
    REQUIRE_FALSE(ctx.has_value());
}

TEST_CASE("TraceContext: reject invalid hex characters", "[tracing]") {
    auto ctx = TraceContext::parse_traceparent(
        "00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-00f067aa0ba902b7-01");
    REQUIRE_FALSE(ctx.has_value());
}

TEST_CASE("TraceContext: reject bad separators", "[tracing]") {
    auto ctx = TraceContext::parse_traceparent(
        "00_4bf92f3577b34da6a3ce929d0e0e4736_00f067aa0ba902b7_01");
    REQUIRE_FALSE(ctx.has_value());
}

TEST_CASE("TraceContext: generate creates valid context", "[tracing]") {
    auto ctx = TraceContext::generate();

    REQUIRE(ctx.trace_id.size() == 32);
    REQUIRE(ctx.span_id.size() == 16);
    REQUIRE(ctx.is_valid());
    REQUIRE(ctx.is_sampled());
}

TEST_CASE("TraceContext: generate unique IDs", "[tracing]") {
    auto ctx1 = TraceContext::generate();
    auto ctx2 = TraceContext::generate();

    REQUIRE(ctx1.trace_id != ctx2.trace_id);
    REQUIRE(ctx1.span_id != ctx2.span_id);
}

TEST_CASE("TraceContext: to_traceparent round-trip", "[tracing]") {
    auto original = TraceContext::generate();
    auto header = original.to_traceparent();

    // Format: "00-{32hex}-{16hex}-{2hex}"
    REQUIRE(header.size() == 55);
    REQUIRE(header.substr(0, 3) == "00-");

    // Parse it back
    auto parsed = TraceContext::parse_traceparent(header);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->trace_id == original.trace_id);
    // parent_span_id will be original's span_id
    REQUIRE(parsed->parent_span_id == original.span_id);
}

TEST_CASE("TraceContext: generate_span_id length", "[tracing]") {
    auto span = TraceContext::generate_span_id();
    REQUIRE(span.size() == 16);
}

TEST_CASE("TraceContext: generate_trace_id length", "[tracing]") {
    auto trace = TraceContext::generate_trace_id();
    REQUIRE(trace.size() == 32);
}

TEST_CASE("TraceContext: is_valid rejects empty IDs", "[tracing]") {
    TraceContext ctx;
    REQUIRE_FALSE(ctx.is_valid());
}

TEST_CASE("TraceContext: is_valid rejects wrong-length IDs", "[tracing]") {
    TraceContext ctx;
    ctx.trace_id = "abcd";  // Too short
    ctx.span_id = "1234567890abcdef";
    REQUIRE_FALSE(ctx.is_valid());
}
