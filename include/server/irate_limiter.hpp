#pragma once

#include "core/types.hpp"
#include <cstdint>
#include <string>

namespace sqlproxy {

/**
 * @brief Abstract rate limiter interface
 *
 * Enables polymorphic rate limiting — local (HierarchicalRateLimiter),
 * queuing (WaitableRateLimiter), or future distributed (Redis) backends.
 */
class IRateLimiter {
public:
    virtual ~IRateLimiter() = default;

    [[nodiscard]] virtual RateLimitResult check(
        const std::string& user, const std::string& database) = 0;

    virtual void set_user_limit(const std::string& user,
                                uint32_t tokens_per_second,
                                uint32_t burst_capacity) = 0;

    virtual void set_database_limit(const std::string& database,
                                    uint32_t tokens_per_second,
                                    uint32_t burst_capacity) = 0;

    virtual void set_user_database_limit(const std::string& user,
                                         const std::string& database,
                                         uint32_t tokens_per_second,
                                         uint32_t burst_capacity) = 0;

    virtual void reset_all() = 0;
};

} // namespace sqlproxy
