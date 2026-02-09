#pragma once

#include "core/types.hpp"
#include <atomic>
#include <chrono>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace sqlproxy {

/**
 * @brief Circuit Breaker for database failure isolation
 *
 * Three states:
 * - CLOSED:     Normal operation, all requests pass through
 * - OPEN:       Failing, reject requests immediately (no DB connection)
 * - HALF_OPEN:  Testing recovery, allow limited requests
 *
 * State transitions:
 * - CLOSED → OPEN:      failure_count >= threshold
 * - OPEN → HALF_OPEN:   timeout elapsed
 * - HALF_OPEN → CLOSED: success_count >= threshold
 * - HALF_OPEN → OPEN:   any failure
 *
 * Benefits:
 * - Prevents cascade failures
 * - Fast-fail during outages (no connection timeout wait)
 * - Automatic recovery detection
 * - Per-database isolation
 *
 * Performance: ~50ns to check state (atomic load)
 */
/**
 * @brief Structured event emitted on circuit breaker state transitions
 */
struct StateChangeEvent {
    CircuitState from;
    CircuitState to;
    std::chrono::system_clock::time_point timestamp;
    std::string breaker_name;
};

class CircuitBreaker {
public:
    /**
     * @brief Configuration
     */
    struct Config {
        uint32_t failure_threshold;     // Failures to trip OPEN
        uint32_t success_threshold;     // Successes to close from HALF_OPEN
        std::chrono::milliseconds timeout;  // Time before trying HALF_OPEN
        uint32_t half_open_max_calls;   // Max concurrent calls in HALF_OPEN

        Config()
            : failure_threshold(15),
              success_threshold(5),
              timeout(5000),
              half_open_max_calls(5) {}
    };

    /**
     * @brief Construct circuit breaker
     * @param name Circuit breaker identifier
     * @param config Configuration
     */
    explicit CircuitBreaker(std::string name, const Config& config = Config());

    /**
     * @brief Check if request can proceed
     * @return true if allowed, false if circuit open
     */
    bool allow_request();

    /**
     * @brief Record successful operation
     */
    void record_success();

    /**
     * @brief Record failed operation (all errors count toward threshold)
     */
    void record_failure();

    /**
     * @brief Record failed operation with error classification
     * @param category Only INFRASTRUCTURE errors count toward threshold
     */
    void record_failure(FailureCategory category);

    /**
     * @brief Get current state
     */
    CircuitState get_state() const;

    /**
     * @brief Get statistics
     */
    CircuitBreakerStats get_stats() const;

    /**
     * @brief Force reset to CLOSED state
     */
    void reset();

    /**
     * @brief Get circuit breaker name
     */
    const std::string& name() const { return name_; }

    /**
     * @brief Register callback for state transitions
     */
    void set_on_state_change(std::function<void(const StateChangeEvent&)> cb);

    /**
     * @brief Get recent state change events (most recent last)
     */
    [[nodiscard]] std::vector<StateChangeEvent> get_recent_events() const;

private:
    /**
     * @brief Attempt state transition
     */
    void try_state_transition();

    /**
     * @brief Transition to OPEN state
     */
    void trip();

    /**
     * @brief Transition to HALF_OPEN state
     */
    void attempt_reset();

    /**
     * @brief Transition to CLOSED state
     */
    void close_circuit();

    std::string name_;
    Config config_;

    // Atomic state
    std::atomic<CircuitState> state_;
    std::atomic<uint64_t> success_count_;
    std::atomic<uint64_t> failure_count_;
    std::atomic<uint64_t> half_open_calls_;

    // Per-category failure counters
    std::atomic<uint64_t> infrastructure_failure_count_{0};
    std::atomic<uint64_t> application_failure_count_{0};
    std::atomic<uint64_t> transient_failure_count_{0};

    // Timestamps
    std::atomic<std::chrono::system_clock::time_point::rep> last_failure_time_;
    std::atomic<std::chrono::system_clock::time_point::rep> opened_time_;

    // State change events
    void emit_transition(CircuitState from, CircuitState to);
    std::function<void(const StateChangeEvent&)> on_state_change_;
    std::deque<StateChangeEvent> recent_events_;
    mutable std::mutex events_mutex_;
    static constexpr size_t kMaxRecentEvents = 100;
    std::atomic<uint64_t> transitions_to_open_{0};
    std::atomic<uint64_t> transitions_to_half_open_{0};
    std::atomic<uint64_t> transitions_to_closed_{0};
};

} // namespace sqlproxy
