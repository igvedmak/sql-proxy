#pragma once

#include <cstdint>
#include <string_view>

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

/**
 * @brief Get the number of rate-limit tokens consumed by a priority level
 */
inline uint32_t priority_token_cost(uint8_t priority) {
    switch (priority) {
        case 3:  return 1;  // HIGH
        case 2:  return 1;  // NORMAL
        case 1:  return 2;  // LOW
        case 0:  return 4;  // BACKGROUND
        default: return 1;  // Unknown → treat as NORMAL
    }
}

/**
 * @brief Parse priority string to numeric value
 * @return priority value (0-3), defaults to 2 (NORMAL) if unrecognized
 */
inline uint8_t parse_priority(std::string_view str) {
    if (str == "high")       return 3;
    if (str == "normal")     return 2;
    if (str == "low")        return 1;
    if (str == "background") return 0;
    return 2;  // default NORMAL
}

/**
 * @brief Convert priority value to string
 */
inline const char* priority_to_string(uint8_t priority) {
    switch (priority) {
        case 0:  return "background";
        case 1:  return "low";
        case 2:  return "normal";
        case 3:  return "high";
        default: return "normal";
    }
}

} // namespace sqlproxy
