#include "tracing/trace_context.hpp"
#include <format>
#include <random>

namespace sqlproxy {

namespace {

bool is_valid_hex(std::string_view s) {
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }
    return true;
}

bool is_all_zeros(std::string_view s) {
    for (char c : s) {
        if (c != '0') return false;
    }
    return true;
}

std::string random_hex(size_t bytes) {
    static thread_local std::random_device rd;
    static thread_local std::mt19937_64 gen(rd());
    static thread_local std::uniform_int_distribution<uint64_t> dis;

    std::string result;
    result.reserve(bytes * 2);

    size_t remaining = bytes;
    while (remaining > 0) {
        uint64_t val = dis(gen);
        size_t chunk = std::min(remaining, size_t(8));
        for (size_t i = 0; i < chunk; ++i) {
            result += std::format("{:02x}", static_cast<uint8_t>(val >> (i * 8)));
        }
        remaining -= chunk;
    }

    return result;
}

} // anonymous namespace

bool TraceContext::is_valid() const {
    return trace_id.size() == 32 && is_valid_hex(trace_id) && !is_all_zeros(trace_id)
        && span_id.size() == 16 && is_valid_hex(span_id) && !is_all_zeros(span_id);
}

TraceContext TraceContext::generate() {
    TraceContext ctx;
    ctx.trace_id = generate_trace_id();
    ctx.span_id = generate_span_id();
    ctx.trace_flags = 0x01; // sampled
    return ctx;
}

std::optional<TraceContext> TraceContext::parse_traceparent(std::string_view header) {
    // Format: "VV-TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT-PPPPPPPPPPPPPPPP-FF"
    // Lengths: 2 + 1 + 32 + 1 + 16 + 1 + 2 = 55

    if (header.size() < 55) return std::nullopt;

    // Validate separators
    if (header[2] != '-' || header[35] != '-' || header[52] != '-') {
        return std::nullopt;
    }

    auto version = header.substr(0, 2);
    auto trace_id = header.substr(3, 32);
    auto parent_id = header.substr(36, 16);
    auto flags = header.substr(53, 2);

    // Version must be "00"
    if (version != "00") return std::nullopt;

    // Validate hex
    if (!is_valid_hex(trace_id) || !is_valid_hex(parent_id) || !is_valid_hex(flags)) {
        return std::nullopt;
    }

    // trace_id must not be all zeros
    if (is_all_zeros(trace_id)) return std::nullopt;

    // parent_id must not be all zeros
    if (is_all_zeros(parent_id)) return std::nullopt;

    TraceContext ctx;
    ctx.trace_id = std::string(trace_id);
    ctx.parent_span_id = std::string(parent_id);
    ctx.span_id = generate_span_id(); // New span for this request

    // Parse flags
    uint8_t flag_val = 0;
    for (char c : flags) {
        flag_val <<= 4;
        if (c >= '0' && c <= '9') flag_val |= (c - '0');
        else if (c >= 'a' && c <= 'f') flag_val |= (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') flag_val |= (c - 'A' + 10);
    }
    ctx.trace_flags = flag_val;

    return ctx;
}

std::string TraceContext::to_traceparent() const {
    return std::format("00-{}-{}-{:02x}", trace_id, span_id, trace_flags);
}

std::string TraceContext::generate_span_id() {
    return random_hex(8); // 8 bytes = 16 hex chars
}

std::string TraceContext::generate_trace_id() {
    return random_hex(16); // 16 bytes = 32 hex chars
}

} // namespace sqlproxy
