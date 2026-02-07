#include "server/waitable_rate_limiter.hpp"

namespace sqlproxy {

WaitableRateLimiter::WaitableRateLimiter(
    std::shared_ptr<IRateLimiter> inner, const Config& config)
    : inner_(std::move(inner)), config_(config) {
    if (config_.queue_enabled) {
        notifier_thread_ = std::thread(&WaitableRateLimiter::notifier_loop, this);
    }
}

WaitableRateLimiter::~WaitableRateLimiter() {
    stop_notifier_.store(true, std::memory_order_release);
    wait_cv_.notify_all();
    if (notifier_thread_.joinable()) {
        notifier_thread_.join();
    }
}

RateLimitResult WaitableRateLimiter::check(
    const std::string& user, const std::string& database) {

    // Fast path: check inner
    auto result = inner_->check(user, database);
    if (result.allowed) return result;

    // If queuing disabled, return rejected immediately (backward compatible)
    if (!config_.queue_enabled) return result;

    // Check queue capacity
    uint32_t depth = current_queue_depth_.load(std::memory_order_relaxed);
    if (depth >= config_.max_queue_depth) {
        return result;  // Queue full
    }

    // Enter queue
    current_queue_depth_.fetch_add(1, std::memory_order_relaxed);
    total_queued_.fetch_add(1, std::memory_order_relaxed);

    auto deadline = std::chrono::steady_clock::now() + config_.queue_timeout;

    // Wait loop: retry inner rate limiter until success or timeout
    std::unique_lock lock(wait_mutex_);
    while (std::chrono::steady_clock::now() < deadline) {
        auto wait_time = std::min(
            std::chrono::milliseconds(10),
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()));

        if (wait_time <= std::chrono::milliseconds::zero()) break;

        wait_cv_.wait_for(lock, wait_time);

        // Unlock while checking rate limiter (avoid holding lock during atomic CAS)
        lock.unlock();
        result = inner_->check(user, database);
        lock.lock();

        if (result.allowed) {
            current_queue_depth_.fetch_sub(1, std::memory_order_relaxed);
            return result;
        }
    }

    // Timeout
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

void WaitableRateLimiter::notifier_loop() {
    while (!stop_notifier_.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        wait_cv_.notify_all();
    }
}

} // namespace sqlproxy
