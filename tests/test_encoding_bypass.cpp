#include <catch2/catch_test_macros.hpp>
#include "security/sql_injection_detector.hpp"

using namespace sqlproxy;

static ParsedQuery make_parsed(StatementType type = StatementType::SELECT) {
    ParsedQuery pq;
    pq.type = type;
    return pq;
}

TEST_CASE("EncodingBypass: URL-encoded tautology detected", "[sqli][encoding]") {
    SqlInjectionDetector detector;
    // "1 OR 1=1" URL-encoded: %31%20OR%20%31%3D%31
    auto result = detector.analyze(
        "%31%20OR%20%31%3D%31",
        "%31%20OR%20%31%3D%31",
        make_parsed());
    CHECK(result.threat_level >= SqlInjectionDetector::ThreatLevel::MEDIUM);
    bool found_encoding = false;
    bool found_tautology = false;
    for (const auto& p : result.patterns_matched) {
        if (p == "ENCODING_BYPASS") found_encoding = true;
        if (p == "TAUTOLOGY") found_tautology = true;
    }
    CHECK(found_encoding);
    CHECK(found_tautology);
}

TEST_CASE("EncodingBypass: HTML entity encoded UNION injection detected", "[sqli][encoding]") {
    SqlInjectionDetector detector;
    // "UNION SELECT" with HTML numeric encoding for space and letters
    // &#85;NION&#32;SELECT = UNION SELECT
    auto result = detector.analyze(
        "SELECT id FROM t WHERE 1=0 &#85;NION&#32;SELECT password FROM users",
        "SELECT id FROM t WHERE 1=0 &#85;NION&#32;SELECT password FROM users",
        make_parsed());
    CHECK(result.threat_level >= SqlInjectionDetector::ThreatLevel::MEDIUM);
    bool found_encoding = false;
    for (const auto& p : result.patterns_matched) {
        if (p == "ENCODING_BYPASS") found_encoding = true;
    }
    CHECK(found_encoding);
}

TEST_CASE("EncodingBypass: double URL encoding detected", "[sqli][encoding]") {
    SqlInjectionDetector detector;
    // Double-encoded: %2531 → %31 → 1, %253D → %3D → =
    // %2531%2520OR%2520%2531%253D%2531 → 1 OR 1=1
    auto result = detector.analyze(
        "%2531%2520OR%2520%2531%253D%2531",
        "%2531%2520OR%2520%2531%253D%2531",
        make_parsed());
    CHECK(result.threat_level >= SqlInjectionDetector::ThreatLevel::MEDIUM);
    bool found_encoding = false;
    for (const auto& p : result.patterns_matched) {
        if (p == "ENCODING_BYPASS") found_encoding = true;
    }
    CHECK(found_encoding);
}

TEST_CASE("EncodingBypass: clean SQL with no encoding is unaffected", "[sqli][encoding]") {
    SqlInjectionDetector detector;
    auto result = detector.analyze(
        "SELECT id, name FROM customers WHERE id = 42",
        "SELECT id, name FROM customers WHERE id = $1",
        make_parsed());
    CHECK(result.threat_level == SqlInjectionDetector::ThreatLevel::NONE);
    for (const auto& p : result.patterns_matched) {
        CHECK(p != "ENCODING_BYPASS");
    }
}

TEST_CASE("EncodingBypass: disabled encoding detection skips check", "[sqli][encoding]") {
    SqlInjectionDetector::Config cfg;
    cfg.encoding_detection_enabled = false;
    SqlInjectionDetector detector(cfg);
    auto result = detector.analyze(
        "%31%20OR%20%31%3D%31",
        "%31%20OR%20%31%3D%31",
        make_parsed());
    for (const auto& p : result.patterns_matched) {
        CHECK(p != "ENCODING_BYPASS");
    }
}
