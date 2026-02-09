#include "server/waitable_rate_limiter.hpp"

namespace sqlproxy {

WaitableRateLimiter::WaitableRateLimiter(
    std::shared_ptr<IRateLimiter> inner, const Config& config)
    : inner_(std::move(inner)), config_(config) {}

WaitableRateLimiter::~WaitableRateLimiter() {
    shutdown_.store(true, std::memory_order_release);
}

RateLimitResult WaitableRateLimiter::check(
    const std::string& user, const std::string& database) {

    // Fast path: check inner
    auto result = inner_->check(user, database);
    if (result.allowed) return result;

    // If queuing disabled, return rejected immediately (backward compatible)
    if (!config_.queue_enabled) return result;

    // Atomic queue depth check (fixes TOCTOU race: increment first, rollback if over)
    uint32_t prev = current_queue_depth_.fetch_add(1, std::memory_order_relaxed);
    if (prev >= config_.max_queue_depth) {
        current_queue_depth_.fetch_sub(1, std::memory_order_relaxed);
        return result;  // Queue full
    }

    total_queued_.fetch_add(1, std::memory_order_relaxed);

    auto deadline = std::chrono::steady_clock::now() + config_.queue_timeout;

    // Sleep-retry loop: each waiter sleeps independently (no mutex contention)
    while (!shutdown_.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < deadline) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        auto sleep_time = std::min(std::chrono::milliseconds(10), remaining);
        if (sleep_time <= std::chrono::milliseconds::zero()) break;

        std::this_thread::sleep_for(sleep_time);

        result = inner_->check(user, database);
        if (result.allowed) {
            current_queue_depth_.fetch_sub(1, std::memory_order_relaxed);
            return result;
        }
    }

    // Timeout or shutdown
    current_queue_depth_.fetch_sub(1, std::memory_order_relaxed);
    total_timeouts_.fetch_add(1, std::memory_order_relaxed);
    return result;
}

void WaitableRateLimiter::set_user_limit(
    const std::string& user, uint32_t tps, uint32_t burst) {
    inner_->set_user_limit(user, tps, burst);
}

void WaitableRateLimiter::set_database_limit(
    const std::string& database, uint32_t tps, uint32_t burst) {
    inner_->set_database_limit(database, tps, burst);
}

void WaitableRateLimiter::set_user_database_limit(
    const std::string& user, const std::string& database,
    uint32_t tps, uint32_t burst) {
    inner_->set_user_database_limit(user, database, tps, burst);
}

void WaitableRateLimiter::reset_all() {
    inner_->reset_all();
}

} // namespace sqlproxy
