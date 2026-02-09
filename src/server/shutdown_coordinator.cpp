#include "server/shutdown_coordinator.hpp"

namespace sqlproxy {

ShutdownCoordinator::ShutdownCoordinator() = default;

ShutdownCoordinator::ShutdownCoordinator(const Config& config)
    : config_(config) {}

void ShutdownCoordinator::initiate_shutdown() {
    shutting_down_.store(true, std::memory_order_release);
    drain_cv_.notify_one();
}

bool ShutdownCoordinator::try_enter_request() {
    if (shutting_down_.load(std::memory_order_acquire)) {
        return false;
    }
    in_flight_.fetch_add(1, std::memory_order_relaxed);
    // Double-check after increment (avoid race with initiate_shutdown)
    if (shutting_down_.load(std::memory_order_acquire)) {
        in_flight_.fetch_sub(1, std::memory_order_relaxed);
        drain_cv_.notify_one();
        return false;
    }
    return true;
}

void ShutdownCoordinator::leave_request() {
    const uint32_t prev = in_flight_.fetch_sub(1, std::memory_order_relaxed);
    if (prev == 1 && shutting_down_.load(std::memory_order_acquire)) {
        drain_cv_.notify_one();
    }
}

bool ShutdownCoordinator::wait_for_drain() {
    std::unique_lock lock(drain_mutex_);
    return drain_cv_.wait_for(lock, config_.shutdown_timeout, [this] {
        return in_flight_.load(std::memory_order_relaxed) == 0;
    });
}

} // namespace sqlproxy
