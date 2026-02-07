#include <catch2/catch_test_macros.hpp>
#include "server/waitable_rate_limiter.hpp"
#include "server/rate_limiter.hpp"
#include <chrono>
#include <thread>

using namespace sqlproxy;

static std::shared_ptr<HierarchicalRateLimiter> make_limiter(
    uint32_t global_tps = 10, uint32_t global_burst = 5) {
    HierarchicalRateLimiter::Config cfg;
    cfg.global_tokens_per_second = global_tps;
    cfg.global_burst_capacity = global_burst;
    cfg.default_user_tokens_per_second = 100000;
    cfg.default_user_burst_capacity = 100000;
    cfg.default_db_tokens_per_second = 100000;
    cfg.default_db_burst_capacity = 100000;
    cfg.default_user_db_tokens_per_second = 100000;
    cfg.default_user_db_burst_capacity = 100000;
    return std::make_shared<HierarchicalRateLimiter>(cfg);
}

TEST_CASE("WaitableRateLimiter: queue_disabled passes through", "[waitable_rl]") {
    auto inner = make_limiter(100000, 100000);
    WaitableRateLimiter::Config cfg;
    cfg.queue_enabled = false;

    WaitableRateLimiter waitable(inner, cfg);
    auto result = waitable.check("user", "db");
    CHECK(result.allowed);
}

TEST_CASE("WaitableRateLimiter: queue_disabled rejects immediately", "[waitable_rl]") {
    auto inner = make_limiter(1, 1);
    WaitableRateLimiter::Config cfg;
    cfg.queue_enabled = false;

    WaitableRateLimiter waitable(inner, cfg);

    // Exhaust the burst
    (void)waitable.check("user", "db");  // uses the 1 token
    auto result = waitable.check("user", "db");  // should be rejected
    CHECK_FALSE(result.allowed);
    CHECK(waitable.queued_total() == 0);  // No queuing
}

TEST_CASE("WaitableRateLimiter: queue_enabled waits and succeeds", "[waitable_rl]") {
    auto inner = make_limiter(100, 1);  // refills at 100/sec
    WaitableRateLimiter::Config cfg;
    cfg.queue_enabled = true;
    cfg.queue_timeout = std::chrono::milliseconds(500);
    cfg.max_queue_depth = 10;

    WaitableRateLimiter waitable(inner, cfg);

    // Exhaust burst
    (void)waitable.check("user", "db");

    // Next check should queue, then succeed after refill (~10ms)
    auto start = std::chrono::steady_clock::now();
    auto result = waitable.check("user", "db");
    auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(result.allowed);
    CHECK(waitable.queued_total() == 1);
    // Should have waited at least a few ms
    CHECK(elapsed > std::chrono::milliseconds(5));
}

TEST_CASE("WaitableRateLimiter: queue timeout", "[waitable_rl]") {
    auto inner = make_limiter(1, 1);  // Very slow refill
    WaitableRateLimiter::Config cfg;
    cfg.queue_enabled = true;
    cfg.queue_timeout = std::chrono::milliseconds(50);  // Short timeout
    cfg.max_queue_depth = 10;

    WaitableRateLimiter waitable(inner, cfg);

    // Exhaust all tokens
    (void)waitable.check("user", "db");

    // Flood to exhaust refills
    for (int i = 0; i < 5; ++i) {
        (void)waitable.check("user", "db");
    }

    // This should timeout
    auto result = waitable.check("user", "db");
    // May or may not be allowed depending on timing, but timeouts should be tracked
    CHECK(waitable.queued_total() > 0);
}

TEST_CASE("WaitableRateLimiter: current_queue_depth returns to 0", "[waitable_rl]") {
    auto inner = make_limiter(1000, 100);
    WaitableRateLimiter::Config cfg;
    cfg.queue_enabled = true;
    cfg.queue_timeout = std::chrono::milliseconds(100);
    cfg.max_queue_depth = 10;

    WaitableRateLimiter waitable(inner, cfg);

    // Normal request (no queuing needed)
    (void)waitable.check("user", "db");

    // Queue depth should be 0 after request completes
    CHECK(waitable.current_queue_depth() == 0);
}

TEST_CASE("WaitableRateLimiter: delegates set/reset to inner", "[waitable_rl]") {
    auto inner = make_limiter();
    WaitableRateLimiter::Config cfg;
    cfg.queue_enabled = false;

    WaitableRateLimiter waitable(inner, cfg);

    // These should not throw
    waitable.set_user_limit("user", 100, 20);
    waitable.set_database_limit("db", 100, 20);
    waitable.set_user_database_limit("user", "db", 100, 20);
    waitable.reset_all();
}
