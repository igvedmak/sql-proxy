#pragma once

#include "server/irate_limiter.hpp"
#include <atomic>
#include <chrono>
#include <memory>
#include <thread>

namespace sqlproxy {

/**
 * @brief Queue-based rate limiter decorator
 *
 * Wraps an IRateLimiter — when tokens are exhausted, waits up to
 * queue_timeout instead of returning immediate 429.
 *
 * Backward-compatible: queue_enabled=false delegates directly to inner.
 */
class WaitableRateLimiter : public IRateLimiter {
public:
    struct Config {
        bool queue_enabled = false;
        std::chrono::milliseconds queue_timeout{5000};
        uint32_t max_queue_depth = 1000;
    };

    WaitableRateLimiter(std::shared_ptr<IRateLimiter> inner, const Config& config);
    ~WaitableRateLimiter() override;

    [[nodiscard]] RateLimitResult check(
        const std::string& user, const std::string& database) override;

    void set_user_limit(const std::string& user,
                        uint32_t tokens_per_second,
                        uint32_t burst_capacity) override;

    void set_database_limit(const std::string& database,
                            uint32_t tokens_per_second,
                            uint32_t burst_capacity) override;

    void set_user_database_limit(const std::string& user,
                                  const std::string& database,
                                  uint32_t tokens_per_second,
                                  uint32_t burst_capacity) override;

    void reset_all() override;

    [[nodiscard]] uint64_t queued_total() const { return total_queued_.load(std::memory_order_relaxed); }
    [[nodiscard]] uint64_t queue_timeouts() const { return total_timeouts_.load(std::memory_order_relaxed); }
    [[nodiscard]] uint32_t current_queue_depth() const { return current_queue_depth_.load(std::memory_order_relaxed); }

    [[nodiscard]] std::shared_ptr<IRateLimiter> get_inner() const { return inner_; }

private:
    std::shared_ptr<IRateLimiter> inner_;
    Config config_;

    std::atomic<uint32_t> current_queue_depth_{0};
    std::atomic<uint64_t> total_queued_{0};
    std::atomic<uint64_t> total_timeouts_{0};

    std::atomic<bool> shutdown_{false};
};

} // namespace sqlproxy
