#include "server/adaptive_rate_controller.hpp"

namespace sqlproxy {

AdaptiveRateController::AdaptiveRateController(
    std::shared_ptr<HierarchicalRateLimiter> rate_limiter,
    const Config& config,
    uint32_t original_global_tps,
    uint32_t original_global_burst)
    : config_(config),
      rate_limiter_(std::move(rate_limiter)),
      original_tps_(original_global_tps),
      original_burst_(original_global_burst),
      current_tps_(original_global_tps) {

    for (size_t i = 0; i < kNumBuckets; ++i) {
        histogram_[i].store(0, std::memory_order_relaxed);
    }

    if (config_.enabled) {
        running_.store(true, std::memory_order_release);
        adjustment_thread_ = std::thread(&AdaptiveRateController::adjustment_loop, this);
    }
}

AdaptiveRateController::~AdaptiveRateController() {
    stop();
}

void AdaptiveRateController::stop() {
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
        return;
    }
    cv_.notify_one();
    if (adjustment_thread_.joinable()) {
        adjustment_thread_.join();
    }
}

void AdaptiveRateController::observe_latency(uint64_t latency_us) {
    const uint64_t latency_ms = latency_us / 1000;

    size_t bucket;
    if (latency_ms < 10) {
        bucket = 0;
    } else if (latency_ms < 50) {
        bucket = 1;
    } else if (latency_ms < 200) {
        bucket = 2;
    } else if (latency_ms < 1000) {
        bucket = 3;
    } else {
        bucket = 4;
    }

    histogram_[bucket].fetch_add(1, std::memory_order_relaxed);
    observations_total_.fetch_add(1, std::memory_order_relaxed);
}

uint32_t AdaptiveRateController::approximate_p95_ms() const {
    // Read histogram snapshot
    uint64_t counts[kNumBuckets];
    uint64_t total = 0;
    for (size_t i = 0; i < kNumBuckets; ++i) {
        counts[i] = histogram_[i].load(std::memory_order_relaxed);
        total += counts[i];
    }

    if (total == 0) return 0;

    // Find bucket where cumulative count reaches 95%
    const uint64_t p95_threshold = (total * 95 + 99) / 100;  // Ceiling division
    uint64_t cumulative = 0;

    // Bucket midpoints: 5ms, 30ms, 125ms, 600ms, 2000ms
    static constexpr uint32_t kBucketMidpoints[] = {5, 30, 125, 600, 2000};

    for (size_t i = 0; i < kNumBuckets; ++i) {
        cumulative += counts[i];
        if (cumulative >= p95_threshold) {
            return kBucketMidpoints[i];
        }
    }

    return kBucketMidpoints[kNumBuckets - 1];
}

AdaptiveRateController::Stats AdaptiveRateController::get_stats() const {
    return Stats{
        .observations_total = observations_total_.load(std::memory_order_relaxed),
        .current_tps = current_tps_.load(std::memory_order_relaxed),
        .original_tps = original_tps_,
        .p95_bucket_ms = approximate_p95_ms(),
        .adjustments_total = adjustments_total_.load(std::memory_order_relaxed),
        .throttle_events = throttle_events_.load(std::memory_order_relaxed),
        .protect_events = protect_events_.load(std::memory_order_relaxed),
    };
}

void AdaptiveRateController::adjustment_loop() {
    while (running_.load(std::memory_order_acquire)) {
        {
            std::unique_lock<std::mutex> lock(cv_mutex_);
            cv_.wait_for(lock,
                std::chrono::seconds(config_.adjustment_interval_seconds),
                [this] { return !running_.load(std::memory_order_acquire); });
        }

        if (!running_.load(std::memory_order_acquire)) break;

        const uint32_t p95 = approximate_p95_ms();
        uint32_t new_tps = original_tps_;

        if (p95 >= config_.throttle_threshold_ms) {
            // Protect mode: 10% of original
            new_tps = std::max(original_tps_ / 10, 1u);
            protect_events_.fetch_add(1, std::memory_order_relaxed);
        } else if (p95 >= config_.latency_target_ms) {
            // Throttle mode: 40% of original
            new_tps = std::max(original_tps_ * 4 / 10, 1u);
            throttle_events_.fetch_add(1, std::memory_order_relaxed);
        }

        const uint32_t old_tps = current_tps_.load(std::memory_order_relaxed);
        if (new_tps != old_tps) {
            // Scale burst proportionally
            const uint32_t new_burst = (original_burst_ * new_tps + original_tps_ / 2) / original_tps_;
            rate_limiter_->adjust_global_rate(new_tps, std::max(new_burst, 1u));
            current_tps_.store(new_tps, std::memory_order_relaxed);
            adjustments_total_.fetch_add(1, std::memory_order_relaxed);
        }

        // Reset histogram for next window
        for (size_t i = 0; i < kNumBuckets; ++i) {
            histogram_[i].store(0, std::memory_order_relaxed);
        }
        observations_total_.store(0, std::memory_order_relaxed);
    }
}

} // namespace sqlproxy
