#include <catch2/catch_test_macros.hpp>
#include "executor/circuit_breaker.hpp"

using namespace sqlproxy;

TEST_CASE("CircuitBreaker: APPLICATION errors don't trip breaker", "[circuit_breaker][classification]") {
    CircuitBreaker::Config cfg;
    cfg.failure_threshold = 3;
    cfg.timeout = std::chrono::milliseconds(1000);
    CircuitBreaker cb("test", cfg);

    // 100 application errors should NOT trip the breaker
    for (int i = 0; i < 100; ++i) {
        cb.record_failure(FailureCategory::APPLICATION);
    }
    CHECK(cb.get_state() == CircuitState::CLOSED);

    auto stats = cb.get_stats();
    CHECK(stats.application_failure_count == 100);
    CHECK(stats.infrastructure_failure_count == 0);
}

TEST_CASE("CircuitBreaker: INFRASTRUCTURE errors trip breaker", "[circuit_breaker][classification]") {
    CircuitBreaker::Config cfg;
    cfg.failure_threshold = 3;
    cfg.timeout = std::chrono::milliseconds(1000);
    CircuitBreaker cb("test", cfg);

    cb.record_failure(FailureCategory::INFRASTRUCTURE);
    cb.record_failure(FailureCategory::INFRASTRUCTURE);
    CHECK(cb.get_state() == CircuitState::CLOSED);

    cb.record_failure(FailureCategory::INFRASTRUCTURE);
    CHECK(cb.get_state() == CircuitState::OPEN);

    auto stats = cb.get_stats();
    CHECK(stats.infrastructure_failure_count == 3);
}

TEST_CASE("CircuitBreaker: TRANSIENT errors don't trip breaker", "[circuit_breaker][classification]") {
    CircuitBreaker::Config cfg;
    cfg.failure_threshold = 3;
    cfg.timeout = std::chrono::milliseconds(1000);
    CircuitBreaker cb("test", cfg);

    for (int i = 0; i < 50; ++i) {
        cb.record_failure(FailureCategory::TRANSIENT);
    }
    CHECK(cb.get_state() == CircuitState::CLOSED);

    auto stats = cb.get_stats();
    CHECK(stats.transient_failure_count == 50);
    CHECK(stats.failure_count == 0);
}

TEST_CASE("CircuitBreaker: mixed errors - only infra counts toward threshold", "[circuit_breaker][classification]") {
    CircuitBreaker::Config cfg;
    cfg.failure_threshold = 5;
    cfg.timeout = std::chrono::milliseconds(1000);
    CircuitBreaker cb("test", cfg);

    // 100 app + 4 infra → still CLOSED
    for (int i = 0; i < 100; ++i) {
        cb.record_failure(FailureCategory::APPLICATION);
    }
    for (int i = 0; i < 4; ++i) {
        cb.record_failure(FailureCategory::INFRASTRUCTURE);
    }
    CHECK(cb.get_state() == CircuitState::CLOSED);

    // 5th infra → OPEN
    cb.record_failure(FailureCategory::INFRASTRUCTURE);
    CHECK(cb.get_state() == CircuitState::OPEN);

    auto stats = cb.get_stats();
    CHECK(stats.infrastructure_failure_count == 5);
    CHECK(stats.application_failure_count == 100);
}

TEST_CASE("CircuitBreaker: per-category stats are tracked correctly", "[circuit_breaker][classification]") {
    CircuitBreaker::Config cfg;
    cfg.failure_threshold = 100;  // High threshold so we don't trip
    CircuitBreaker cb("test", cfg);

    cb.record_failure(FailureCategory::INFRASTRUCTURE);
    cb.record_failure(FailureCategory::INFRASTRUCTURE);
    cb.record_failure(FailureCategory::APPLICATION);
    cb.record_failure(FailureCategory::APPLICATION);
    cb.record_failure(FailureCategory::APPLICATION);
    cb.record_failure(FailureCategory::TRANSIENT);

    auto stats = cb.get_stats();
    CHECK(stats.infrastructure_failure_count == 2);
    CHECK(stats.application_failure_count == 3);
    CHECK(stats.transient_failure_count == 1);

    // Reset clears all counters
    cb.reset();
    stats = cb.get_stats();
    CHECK(stats.infrastructure_failure_count == 0);
    CHECK(stats.application_failure_count == 0);
    CHECK(stats.transient_failure_count == 0);
    CHECK(stats.state == CircuitState::CLOSED);
}
