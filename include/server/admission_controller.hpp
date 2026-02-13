#pragma once

#include "server/request_priority.hpp"

#include <atomic>
#include <cstdint>

namespace sqlproxy {

/**
 * @brief Priority-aware admission controller
 *
 * Under load, rejects lower-priority requests first:
 * - When utilization < 70%: admit all
 * - When 70-85%: reject BACKGROUND
 * - When 85-95%: reject BACKGROUND + LOW
 * - When > 95%: reject BACKGROUND + LOW + NORMAL (only HIGH passes)
 *
 * Utilization = active_requests / max_concurrent_requests
 * Thread-safe via atomic operations.
 */
class AdmissionController {
public:
    struct Config {
        uint32_t max_concurrent = 1000;
        float tier1_threshold = 0.70f;  // reject BACKGROUND
        float tier2_threshold = 0.85f;  // reject LOW
        float tier3_threshold = 0.95f;  // reject NORMAL
    };

    AdmissionController();
    explicit AdmissionController(const Config& config);

    /**
     * @brief Try to admit a request. Returns true if admitted.
     *
     * If admitted, caller MUST call release() when done.
     */
    [[nodiscard]] bool try_admit(PriorityLevel priority);

    /**
     * @brief Release an admitted request slot
     */
    void release();

    struct Stats {
        uint64_t admitted;
        uint64_t rejected;
        uint32_t active;
        uint32_t max_concurrent;
    };
    [[nodiscard]] Stats get_stats() const;

private:
    Config config_;
    std::atomic<uint32_t> active_{0};
    std::atomic<uint64_t> admitted_{0};
    std::atomic<uint64_t> rejected_{0};
};

} // namespace sqlproxy
