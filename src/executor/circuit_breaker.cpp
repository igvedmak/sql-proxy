#include "executor/circuit_breaker.hpp"

namespace sqlproxy {

CircuitBreaker::CircuitBreaker(std::string name, const Config& config)
    : name_(std::move(name)),
      config_(config),
      state_(CircuitState::CLOSED),
      success_count_(0),
      failure_count_(0),
      half_open_calls_(0),
      last_failure_time_(0),
      opened_time_(0) {}

bool CircuitBreaker::allow_request() {
    CircuitState current_state = state_.load(std::memory_order_acquire);

    switch (current_state) {
        case CircuitState::CLOSED:
            // Normal operation - allow all requests
            return true;

        case CircuitState::OPEN: {
            // Check if timeout elapsed
            const auto now = std::chrono::system_clock::now();
            const auto opened_time = std::chrono::system_clock::time_point(
                std::chrono::system_clock::time_point::duration(
                    opened_time_.load(std::memory_order_acquire)
                )
            );

            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - opened_time
            );

            if (elapsed >= config_.timeout) {
                // Timeout elapsed - try HALF_OPEN
                attempt_reset();
                return true; // Allow this request
            }

            // Still in timeout - reject
            return false;
        }

        case CircuitState::HALF_OPEN: {
            // Allow limited concurrent calls
            const uint64_t current_calls = half_open_calls_.load(std::memory_order_acquire);
            if (current_calls >= config_.half_open_max_calls) {
                return false; // Too many concurrent test calls
            }

            // Increment half-open calls
            half_open_calls_.fetch_add(1, std::memory_order_release);
            return true;
        }
    }

    return false;
}

void CircuitBreaker::record_success() {
    CircuitState current_state = state_.load(std::memory_order_acquire);

    if (current_state == CircuitState::HALF_OPEN) {
        // Decrement half-open calls
        half_open_calls_.fetch_sub(1, std::memory_order_release);

        // Increment success count
        const uint64_t successes = success_count_.fetch_add(1, std::memory_order_release) + 1;

        // Check if enough successes to close circuit
        if (successes >= config_.success_threshold) {
            close_circuit();
        }
    } else if (current_state == CircuitState::CLOSED) {
        // Reset failure count on success in CLOSED state
        if (failure_count_.load(std::memory_order_relaxed) > 0) {
            failure_count_.store(0, std::memory_order_relaxed);
        }
    }
}

void CircuitBreaker::record_failure() {
    CircuitState current_state = state_.load(std::memory_order_acquire);

    // Update last failure time
    const auto now = std::chrono::system_clock::now();
    last_failure_time_.store(
        now.time_since_epoch().count(),
        std::memory_order_release
    );

    if (current_state == CircuitState::HALF_OPEN) {
        // Any failure in HALF_OPEN → back to OPEN
        half_open_calls_.fetch_sub(1, std::memory_order_release);
        trip();
    } else if (current_state == CircuitState::CLOSED) {
        // Increment failure count
        const uint64_t failures = failure_count_.fetch_add(1, std::memory_order_release) + 1;

        // Check if threshold reached
        if (failures >= config_.failure_threshold) {
            trip();
        }
    }
}

CircuitState CircuitBreaker::get_state() const {
    return state_.load(std::memory_order_acquire);
}

CircuitBreakerStats CircuitBreaker::get_stats() const {
    CircuitBreakerStats stats;

    stats.state = state_.load(std::memory_order_acquire);
    stats.success_count = success_count_.load(std::memory_order_relaxed);
    stats.failure_count = failure_count_.load(std::memory_order_relaxed);

    const auto last_failure_rep = last_failure_time_.load(std::memory_order_acquire);
    if (last_failure_rep > 0) {
        stats.last_failure = std::chrono::system_clock::time_point(
            std::chrono::system_clock::time_point::duration(last_failure_rep)
        );
    }

    const auto opened_rep = opened_time_.load(std::memory_order_acquire);
    if (opened_rep > 0) {
        stats.opened_at = std::chrono::system_clock::time_point(
            std::chrono::system_clock::time_point::duration(opened_rep)
        );
    }

    return stats;
}

void CircuitBreaker::reset() {
    state_.store(CircuitState::CLOSED, std::memory_order_release);
    success_count_.store(0, std::memory_order_relaxed);
    failure_count_.store(0, std::memory_order_relaxed);
    half_open_calls_.store(0, std::memory_order_relaxed);
    last_failure_time_.store(0, std::memory_order_relaxed);
    opened_time_.store(0, std::memory_order_relaxed);
}

void CircuitBreaker::trip() {
    // Try CLOSED → OPEN first
    CircuitState expected = CircuitState::CLOSED;
    if (state_.compare_exchange_strong(expected, CircuitState::OPEN,
                                       std::memory_order_release,
                                       std::memory_order_acquire)) {
        const auto now = std::chrono::system_clock::now();
        opened_time_.store(now.time_since_epoch().count(), std::memory_order_release);
        return;  // Early return - skip HALF_OPEN path
    }

    // Try HALF_OPEN → OPEN (failure during recovery)
    expected = CircuitState::HALF_OPEN;
    if (state_.compare_exchange_strong(expected, CircuitState::OPEN,
                                       std::memory_order_release,
                                       std::memory_order_acquire)) {
        const auto now = std::chrono::system_clock::now();
        opened_time_.store(now.time_since_epoch().count(), std::memory_order_release);
    }
}

void CircuitBreaker::attempt_reset() {
    CircuitState expected = CircuitState::OPEN;
    if (state_.compare_exchange_strong(expected, CircuitState::HALF_OPEN,
                                       std::memory_order_release,
                                       std::memory_order_acquire)) {
        // Successfully transitioned to HALF_OPEN
        success_count_.store(0, std::memory_order_relaxed);
        failure_count_.store(0, std::memory_order_relaxed);
        half_open_calls_.store(0, std::memory_order_relaxed);
    }
}

void CircuitBreaker::close_circuit() {
    CircuitState expected = CircuitState::HALF_OPEN;
    if (state_.compare_exchange_strong(expected, CircuitState::CLOSED,
                                       std::memory_order_release,
                                       std::memory_order_acquire)) {
        // Successfully closed circuit
        success_count_.store(0, std::memory_order_relaxed);
        failure_count_.store(0, std::memory_order_relaxed);
        half_open_calls_.store(0, std::memory_order_relaxed);
    }
}

} // namespace sqlproxy
