#include "tracing/span.hpp"
#include "core/request_context.hpp"
#include "tracing/trace_context.hpp"

namespace sqlproxy {

ScopedSpan::ScopedSpan(RequestContext& ctx, const char* operation)
    : ctx_(ctx) {
    span_.span_id = TraceContext::generate_span_id();
    span_.parent_span_id = ctx.trace_context.span_id;
    span_.operation = operation;
    span_.start_time = std::chrono::steady_clock::now();
}

ScopedSpan::~ScopedSpan() {
    span_.end_time = std::chrono::steady_clock::now();
    ctx_.spans.push_back(std::move(span_));
}

} // namespace sqlproxy
