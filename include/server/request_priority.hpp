#pragma once

#include <cstdint>
#include <string_view>
#include <unordered_map>

namespace sqlproxy {

/**
 * @brief Request priority levels for weighted rate limiting
 *
 * Higher priority requests consume fewer tokens:
 *   HIGH       = 1 token  (fast path, priority access)
 *   NORMAL     = 1 token  (default)
 *   LOW        = 2 tokens (penalized, batch jobs)
 *   BACKGROUND = 4 tokens (heavily penalized, maintenance)
 */
enum class PriorityLevel : uint8_t {
    BACKGROUND = 0,
    LOW = 1,
    NORMAL = 2,
    HIGH = 3
};

// String constants for priority level names
inline constexpr std::string_view kPriorityHigh       = "high";
inline constexpr std::string_view kPriorityNormal     = "normal";
inline constexpr std::string_view kPriorityLow        = "low";
inline constexpr std::string_view kPriorityBackground = "background";

/**
 * @brief Get the number of rate-limit tokens consumed by a priority level
 */
inline uint32_t priority_token_cost(PriorityLevel priority) {
    switch (priority) {
        case PriorityLevel::HIGH:       return 1;
        case PriorityLevel::NORMAL:     return 1;
        case PriorityLevel::LOW:        return 2;
        case PriorityLevel::BACKGROUND: return 4;
        default:                        return 1;
    }
}

/**
 * @brief Parse priority string to PriorityLevel enum (O(1) hash lookup)
 * @return PriorityLevel, defaults to NORMAL if unrecognized
 */
inline PriorityLevel parse_priority(std::string_view str) {
    static const std::unordered_map<std::string_view, PriorityLevel> kMap = {
        {kPriorityHigh,       PriorityLevel::HIGH},
        {kPriorityNormal,     PriorityLevel::NORMAL},
        {kPriorityLow,        PriorityLevel::LOW},
        {kPriorityBackground, PriorityLevel::BACKGROUND},
    };
    const auto it = kMap.find(str);
    return (it != kMap.end()) ? it->second : PriorityLevel::NORMAL;
}

/**
 * @brief Convert PriorityLevel to string
 */
inline const char* priority_to_string(PriorityLevel priority) {
    switch (priority) {
        case PriorityLevel::BACKGROUND: return "background";
        case PriorityLevel::LOW:        return "low";
        case PriorityLevel::NORMAL:     return "normal";
        case PriorityLevel::HIGH:       return "high";
        default:                        return "normal";
    }
}

} // namespace sqlproxy
