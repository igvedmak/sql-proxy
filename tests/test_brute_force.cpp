#include <catch2/catch_test_macros.hpp>
#include "security/brute_force_protector.hpp"
#include <thread>

using namespace sqlproxy;

TEST_CASE("BruteForce: clean login not blocked", "[brute_force]") {
    BruteForceProtector protector;
    auto status = protector.is_blocked("10.0.0.1", "alice");
    CHECK_FALSE(status.blocked);
    CHECK(status.retry_after_seconds == 0);
}

TEST_CASE("BruteForce: exceeding max_attempts triggers lockout", "[brute_force]") {
    BruteForceProtector::Config cfg;
    cfg.max_attempts = 3;
    cfg.window_seconds = 60;
    cfg.lockout_seconds = 10;
    BruteForceProtector protector(cfg);

    // Record 3 failures
    for (int i = 0; i < 3; ++i) {
        protector.record_failure("10.0.0.1", "alice");
    }

    auto status = protector.is_blocked("10.0.0.1", "alice");
    CHECK(status.blocked);
    CHECK(status.retry_after_seconds > 0);
    CHECK(status.retry_after_seconds <= 10);
}

TEST_CASE("BruteForce: successful login resets counter", "[brute_force]") {
    BruteForceProtector::Config cfg;
    cfg.max_attempts = 5;
    cfg.window_seconds = 60;
    cfg.lockout_seconds = 300;
    BruteForceProtector protector(cfg);

    // Record 4 failures (below threshold)
    for (int i = 0; i < 4; ++i) {
        protector.record_failure("10.0.0.1", "alice");
    }

    // Successful login should reset
    protector.record_success("10.0.0.1", "alice");

    // Should not be blocked
    auto status = protector.is_blocked("10.0.0.1", "alice");
    CHECK_FALSE(status.blocked);

    // Record 4 more failures (still below threshold since reset)
    for (int i = 0; i < 4; ++i) {
        protector.record_failure("10.0.0.1", "alice");
    }

    status = protector.is_blocked("10.0.0.1", "alice");
    CHECK_FALSE(status.blocked);
}

TEST_CASE("BruteForce: exponential backoff increases lockout duration", "[brute_force]") {
    BruteForceProtector::Config cfg;
    cfg.max_attempts = 2;
    cfg.window_seconds = 60;
    cfg.lockout_seconds = 1;
    cfg.max_lockout_seconds = 10;
    BruteForceProtector protector(cfg);

    // First lockout: 1 second
    protector.record_failure("10.0.0.1", "alice");
    protector.record_failure("10.0.0.1", "alice");

    auto status1 = protector.is_blocked("10.0.0.1", "alice");
    CHECK(status1.blocked);
    CHECK(status1.retry_after_seconds <= 1);

    // Wait for first lockout to expire
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    // Second lockout: 2 seconds (exponential)
    protector.record_failure("10.0.0.1", "alice");
    protector.record_failure("10.0.0.1", "alice");

    auto status2 = protector.is_blocked("10.0.0.1", "alice");
    CHECK(status2.blocked);
    CHECK(status2.retry_after_seconds <= 2);
}

TEST_CASE("BruteForce: disabled protector never blocks", "[brute_force]") {
    BruteForceProtector::Config cfg;
    cfg.enabled = false;
    cfg.max_attempts = 1;
    BruteForceProtector protector(cfg);

    // Even with many failures, should not block
    for (int i = 0; i < 100; ++i) {
        protector.record_failure("10.0.0.1", "alice");
    }

    auto status = protector.is_blocked("10.0.0.1", "alice");
    CHECK_FALSE(status.blocked);
}
