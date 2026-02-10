#pragma once

#include "server/rate_limiter.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

namespace sqlproxy {

/**
 * @brief Adaptive rate limiting controller
 *
 * Monitors backend latency P95 and automatically adjusts
 * the global rate limit to protect the database under load.
 *
 * Adjustment rules:
 *   P95 < latency_target_ms      → full rate (original config)
 *   P95 in [target, throttle)    → reduce to 40% of original
 *   P95 >= throttle_threshold_ms → reduce to 10% (protect mode)
 *
 * Thread-safe: observe_latency() is lock-free (atomic histogram).
 * Background thread adjusts every adjustment_interval_seconds.
 */
class AdaptiveRateController {
public:
    struct Config {
        bool enabled = false;
        uint32_t adjustment_interval_seconds = 10;
        uint32_t latency_target_ms = 50;
        uint32_t throttle_threshold_ms = 200;
    };

    struct Stats {
        uint64_t observations_total;
        uint32_t current_tps;
        uint32_t original_tps;
        uint32_t p95_bucket_ms;   // Approximate P95 (bucket midpoint)
        uint64_t adjustments_total;
        uint64_t throttle_events;  // Times reduced to 40%
        uint64_t protect_events;   // Times reduced to 10%
    };

    AdaptiveRateController(
        std::shared_ptr<HierarchicalRateLimiter> rate_limiter,
        const Config& config,
        uint32_t original_global_tps,
        uint32_t original_global_burst);

    ~AdaptiveRateController();

    /**
     * @brief Record an observed query latency (thread-safe, lock-free)
     * @param latency_us Execution time in microseconds
     */
    void observe_latency(uint64_t latency_us);

    /**
     * @brief Get current stats
     */
    [[nodiscard]] Stats get_stats() const;

    void stop();

private:
    void adjustment_loop();
    uint32_t approximate_p95_ms() const;

    Config config_;
    std::shared_ptr<HierarchicalRateLimiter> rate_limiter_;
    uint32_t original_tps_;
    uint32_t original_burst_;

    // Latency histogram: 5 buckets
    // [0] 0-10ms, [1] 10-50ms, [2] 50-200ms, [3] 200-1000ms, [4] 1000ms+
    static constexpr size_t kNumBuckets = 5;
    std::atomic<uint64_t> histogram_[kNumBuckets]{};
    std::atomic<uint64_t> observations_total_{0};

    // Current state
    std::atomic<uint32_t> current_tps_;
    std::atomic<uint64_t> adjustments_total_{0};
    std::atomic<uint64_t> throttle_events_{0};
    std::atomic<uint64_t> protect_events_{0};

    // Background thread
    std::thread adjustment_thread_;
    std::atomic<bool> running_{false};
    std::mutex cv_mutex_;
    std::condition_variable cv_;
};

} // namespace sqlproxy
