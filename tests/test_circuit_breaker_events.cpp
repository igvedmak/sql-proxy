#include <catch2/catch_test_macros.hpp>
#include "executor/circuit_breaker.hpp"
#include <thread>

using namespace sqlproxy;

TEST_CASE("CircuitBreaker: state change event emitted on CLOSED->OPEN", "[circuit_breaker][events]") {
    CircuitBreaker::Config cfg;
    cfg.failure_threshold = 3;
    cfg.timeout = std::chrono::milliseconds(5000);
    CircuitBreaker cb("test-breaker", cfg);

    std::vector<StateChangeEvent> captured;
    cb.set_on_state_change([&](const StateChangeEvent& e) {
        captured.push_back(e);
    });

    // Trip the breaker
    cb.record_failure(FailureCategory::INFRASTRUCTURE);
    cb.record_failure(FailureCategory::INFRASTRUCTURE);
    cb.record_failure(FailureCategory::INFRASTRUCTURE);

    CHECK(cb.get_state() == CircuitState::OPEN);
    REQUIRE(captured.size() == 1);
    CHECK(captured[0].from == CircuitState::CLOSED);
    CHECK(captured[0].to == CircuitState::OPEN);
    CHECK(captured[0].breaker_name == "test-breaker");
}

TEST_CASE("CircuitBreaker: full cycle produces 3 events", "[circuit_breaker][events]") {
    CircuitBreaker::Config cfg;
    cfg.failure_threshold = 2;
    cfg.success_threshold = 1;
    cfg.timeout = std::chrono::milliseconds(10);
    cfg.half_open_max_calls = 5;
    CircuitBreaker cb("cycle-test", cfg);

    std::vector<StateChangeEvent> captured;
    cb.set_on_state_change([&](const StateChangeEvent& e) {
        captured.push_back(e);
    });

    // CLOSED -> OPEN
    cb.record_failure(FailureCategory::INFRASTRUCTURE);
    cb.record_failure(FailureCategory::INFRASTRUCTURE);
    CHECK(cb.get_state() == CircuitState::OPEN);

    // Wait for timeout to allow HALF_OPEN transition
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // OPEN -> HALF_OPEN (triggered by allow_request)
    cb.allow_request();
    CHECK(cb.get_state() == CircuitState::HALF_OPEN);

    // HALF_OPEN -> CLOSED (success)
    cb.record_success();
    CHECK(cb.get_state() == CircuitState::CLOSED);

    REQUIRE(captured.size() == 3);
    CHECK(captured[0].from == CircuitState::CLOSED);
    CHECK(captured[0].to == CircuitState::OPEN);
    CHECK(captured[1].from == CircuitState::OPEN);
    CHECK(captured[1].to == CircuitState::HALF_OPEN);
    CHECK(captured[2].from == CircuitState::HALF_OPEN);
    CHECK(captured[2].to == CircuitState::CLOSED);
}

TEST_CASE("CircuitBreaker: HALF_OPEN->OPEN on failure during recovery", "[circuit_breaker][events]") {
    CircuitBreaker::Config cfg;
    cfg.failure_threshold = 2;
    cfg.success_threshold = 3;
    cfg.timeout = std::chrono::milliseconds(10);
    cfg.half_open_max_calls = 5;
    CircuitBreaker cb("recovery-fail", cfg);

    // Trip to OPEN
    cb.record_failure(FailureCategory::INFRASTRUCTURE);
    cb.record_failure(FailureCategory::INFRASTRUCTURE);
    CHECK(cb.get_state() == CircuitState::OPEN);

    // Wait and transition to HALF_OPEN
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    cb.allow_request();
    CHECK(cb.get_state() == CircuitState::HALF_OPEN);

    // Fail during recovery -> back to OPEN
    cb.record_failure(FailureCategory::INFRASTRUCTURE);
    CHECK(cb.get_state() == CircuitState::OPEN);

    auto events = cb.get_recent_events();
    REQUIRE(events.size() == 3);
    CHECK(events[0].to == CircuitState::OPEN);
    CHECK(events[1].to == CircuitState::HALF_OPEN);
    CHECK(events[2].from == CircuitState::HALF_OPEN);
    CHECK(events[2].to == CircuitState::OPEN);
}

TEST_CASE("CircuitBreaker: event deque capped at 100", "[circuit_breaker][events]") {
    CircuitBreaker::Config cfg;
    cfg.failure_threshold = 1;
    cfg.success_threshold = 1;
    cfg.timeout = std::chrono::milliseconds(1);
    cfg.half_open_max_calls = 5;
    CircuitBreaker cb("cap-test", cfg);

    // Generate >100 transitions by cycling CLOSED->OPEN->HALF_OPEN->CLOSED
    for (int i = 0; i < 50; ++i) {
        cb.record_failure(FailureCategory::INFRASTRUCTURE);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        cb.allow_request();
        cb.record_success();
    }
    // 50 cycles × 3 events = 150 total generated

    auto events = cb.get_recent_events();
    CHECK(events.size() == 100);  // Capped at kMaxRecentEvents
}

TEST_CASE("CircuitBreaker: get_recent_events returns events in chronological order", "[circuit_breaker][events]") {
    CircuitBreaker::Config cfg;
    cfg.failure_threshold = 2;
    cfg.success_threshold = 1;
    cfg.timeout = std::chrono::milliseconds(10);
    cfg.half_open_max_calls = 5;
    CircuitBreaker cb("order-test", cfg);

    // CLOSED -> OPEN
    cb.record_failure(FailureCategory::INFRASTRUCTURE);
    cb.record_failure(FailureCategory::INFRASTRUCTURE);

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // OPEN -> HALF_OPEN
    cb.allow_request();

    // HALF_OPEN -> CLOSED
    cb.record_success();

    auto events = cb.get_recent_events();
    REQUIRE(events.size() == 3);

    // Chronological order: timestamps must be non-decreasing
    CHECK(events[0].timestamp <= events[1].timestamp);
    CHECK(events[1].timestamp <= events[2].timestamp);

    // Reset clears events
    cb.reset();
    auto after_reset = cb.get_recent_events();
    CHECK(after_reset.empty());
}
