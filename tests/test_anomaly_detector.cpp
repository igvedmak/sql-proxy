#include <catch2/catch_test_macros.hpp>
#include "security/anomaly_detector.hpp"

using namespace sqlproxy;

// ============================================================================
// Profile creation
// ============================================================================

TEST_CASE("New user creates profile on record", "[anomaly]") {
    AnomalyDetector detector;
    CHECK(detector.tracked_users() == 0);

    detector.record("alice", {"customers"}, 12345);
    CHECK(detector.tracked_users() == 1);

    detector.record("bob", {"orders"}, 67890);
    CHECK(detector.tracked_users() == 2);
}

// ============================================================================
// Normal queries — no anomalies for new users
// ============================================================================

TEST_CASE("First query from new user has no anomalies", "[anomaly]") {
    AnomalyDetector detector;
    auto result = detector.check("alice", {"customers"}, 12345);
    CHECK_FALSE(result.is_anomalous);
    CHECK(result.anomaly_score < 0.5);
}

// ============================================================================
// New table access detection
// ============================================================================

TEST_CASE("New table access detected after baseline", "[anomaly]") {
    AnomalyDetector::Config cfg;
    cfg.new_table_alert_after_queries = 5;
    AnomalyDetector detector(cfg);

    // Build baseline with 10 queries on known tables
    for (int i = 0; i < 10; ++i) {
        detector.record("alice", {"customers"}, 100 + i);
    }

    // Access a new table
    auto result = detector.check("alice", {"secret_data"}, 999);
    CHECK(result.is_anomalous);

    bool found_new_table = false;
    for (const auto& a : result.anomalies) {
        if (a.find("NEW_TABLE") != std::string::npos) {
            found_new_table = true;
            break;
        }
    }
    CHECK(found_new_table);
}

// ============================================================================
// Known table access — no anomaly
// ============================================================================

TEST_CASE("Known table access does not trigger anomaly", "[anomaly]") {
    AnomalyDetector::Config cfg;
    cfg.new_table_alert_after_queries = 5;
    AnomalyDetector detector(cfg);

    for (int i = 0; i < 10; ++i) {
        detector.record("alice", {"customers"}, 100);
    }

    auto result = detector.check("alice", {"customers"}, 100);
    // Known table + known fingerprint: should not be anomalous
    CHECK_FALSE(result.is_anomalous);
}

// ============================================================================
// New query fingerprint detection
// ============================================================================

TEST_CASE("New query fingerprint detected after baseline", "[anomaly]") {
    AnomalyDetector::Config cfg;
    cfg.new_table_alert_after_queries = 5;
    AnomalyDetector detector(cfg);

    // Build baseline: same fingerprint
    for (int i = 0; i < 10; ++i) {
        detector.record("alice", {"customers"}, 100);
    }

    // New fingerprint on known table
    auto result = detector.check("alice", {"customers"}, 999);
    // Should detect new query pattern (but may not be "anomalous" by itself)
    bool found_new_pattern = false;
    for (const auto& a : result.anomalies) {
        if (a.find("NEW_QUERY_PATTERN") != std::string::npos) {
            found_new_pattern = true;
            break;
        }
    }
    CHECK(found_new_pattern);
}

// ============================================================================
// Disabled detector
// ============================================================================

TEST_CASE("Disabled anomaly detector returns no anomalies", "[anomaly]") {
    AnomalyDetector::Config cfg;
    cfg.enabled = false;
    AnomalyDetector detector(cfg);

    auto result = detector.check("alice", {"secret_data"}, 999);
    CHECK_FALSE(result.is_anomalous);
    CHECK(result.anomaly_score == 0.0);
}

// ============================================================================
// Multiple users tracked independently
// ============================================================================

TEST_CASE("Multiple users tracked independently", "[anomaly]") {
    AnomalyDetector detector;

    detector.record("alice", {"customers"}, 100);
    detector.record("bob", {"orders"}, 200);

    CHECK(detector.tracked_users() == 2);

    // Alice accessing orders is new for her
    auto result = detector.check("alice", {"orders"}, 200);
    // Bob accessing orders is known for him
    auto result2 = detector.check("bob", {"orders"}, 200);

    // We don't assert specific scores since it depends on baseline,
    // but both should succeed without throwing
    CHECK(result.anomaly_score >= 0.0);
    CHECK(result2.anomaly_score >= 0.0);
}

// ============================================================================
// Anomaly score is bounded
// ============================================================================

TEST_CASE("Anomaly score is between 0 and 1", "[anomaly]") {
    AnomalyDetector detector;

    // Build some baseline
    for (int i = 0; i < 20; ++i) {
        detector.record("alice", {"customers"}, 100);
    }

    auto result = detector.check("alice", {"secret", "hidden"}, 999);
    CHECK(result.anomaly_score >= 0.0);
    CHECK(result.anomaly_score <= 1.0);
}
