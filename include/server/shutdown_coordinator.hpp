#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>

namespace sqlproxy {

class ShutdownCoordinator {
public:
    struct Config {
        std::chrono::milliseconds shutdown_timeout{30000};
    };

    ShutdownCoordinator();
    explicit ShutdownCoordinator(const Config& config);

    /// Called by signal handler to initiate shutdown
    void initiate_shutdown();

    /// Called at start of each request. Returns false if shutting down.
    [[nodiscard]] bool try_enter_request();

    /// Called when request completes.
    void leave_request();

    /// Blocks until all in-flight requests complete or timeout.
    /// Returns true if drained cleanly, false if timed out.
    [[nodiscard]] bool wait_for_drain();

    [[nodiscard]] bool is_shutting_down() const {
        return shutting_down_.load(std::memory_order_acquire);
    }

    [[nodiscard]] uint32_t in_flight_count() const {
        return in_flight_.load(std::memory_order_relaxed);
    }

private:
    Config config_;
    std::atomic<bool> shutting_down_{false};
    std::atomic<uint32_t> in_flight_{0};
    std::mutex drain_mutex_;
    std::condition_variable drain_cv_;
};

} // namespace sqlproxy
