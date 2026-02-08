#include <catch2/catch_test_macros.hpp>
#include "security/sql_injection_detector.hpp"

using namespace sqlproxy;

// Helper: build a minimal ParsedQuery for testing
static ParsedQuery make_parsed(StatementType type = StatementType::SELECT) {
    ParsedQuery pq;
    pq.type = type;
    return pq;
}

// ============================================================================
// Clean SQL — should pass through
// ============================================================================

TEST_CASE("Clean SELECT passes injection check", "[sqli]") {
    SqlInjectionDetector detector;
    auto result = detector.analyze(
        "SELECT id, name FROM customers WHERE id = 42",
        "SELECT id, name FROM customers WHERE id = $1",
        make_parsed());
    CHECK(result.threat_level == SqlInjectionDetector::ThreatLevel::NONE);
    CHECK_FALSE(result.should_block);
    CHECK(result.patterns_matched.empty());
}

TEST_CASE("Clean INSERT passes injection check", "[sqli]") {
    SqlInjectionDetector detector;
    auto result = detector.analyze(
        "INSERT INTO orders (customer_id, total) VALUES (1, 99.99)",
        "INSERT INTO orders (customer_id, total) VALUES ($1, $2)",
        make_parsed(StatementType::INSERT));
    CHECK(result.threat_level == SqlInjectionDetector::ThreatLevel::NONE);
    CHECK_FALSE(result.should_block);
}

// ============================================================================
// Tautology detection
// ============================================================================

TEST_CASE("Detects numeric tautology 1=1", "[sqli]") {
    SqlInjectionDetector detector;
    auto result = detector.analyze(
        "SELECT * FROM users WHERE id = 1 OR 1=1",
        "SELECT * FROM users WHERE id = $1 OR 1=1",
        make_parsed());
    CHECK(result.threat_level >= SqlInjectionDetector::ThreatLevel::HIGH);
    CHECK(result.should_block);
    CHECK_FALSE(result.patterns_matched.empty());
}

TEST_CASE("Detects string tautology 'a'='a'", "[sqli]") {
    SqlInjectionDetector detector;
    auto result = detector.analyze(
        "SELECT * FROM users WHERE name = '' OR 'a'='a'",
        "SELECT * FROM users WHERE name = $1 OR 'a'='a'",
        make_parsed());
    CHECK(result.threat_level >= SqlInjectionDetector::ThreatLevel::HIGH);
    CHECK(result.should_block);
}

TEST_CASE("Detects OR true tautology", "[sqli]") {
    SqlInjectionDetector detector;
    auto result = detector.analyze(
        "SELECT * FROM users WHERE id = 1 OR true",
        "SELECT * FROM users WHERE id = $1 OR true",
        make_parsed());
    CHECK(result.threat_level >= SqlInjectionDetector::ThreatLevel::HIGH);
    CHECK(result.should_block);
}

// ============================================================================
// UNION injection
// ============================================================================

TEST_CASE("Detects UNION SELECT injection", "[sqli]") {
    SqlInjectionDetector detector;
    auto result = detector.analyze(
        "SELECT name FROM users WHERE id = 1 UNION SELECT password FROM admin",
        "SELECT name FROM users WHERE id = $1 UNION SELECT password FROM admin",
        make_parsed());
    CHECK(result.threat_level >= SqlInjectionDetector::ThreatLevel::CRITICAL);
    CHECK(result.should_block);
}

TEST_CASE("Detects UNION ALL SELECT injection", "[sqli]") {
    SqlInjectionDetector detector;
    auto result = detector.analyze(
        "SELECT id FROM t UNION ALL SELECT secret FROM keys",
        "SELECT id FROM t UNION ALL SELECT secret FROM keys",
        make_parsed());
    CHECK(result.threat_level >= SqlInjectionDetector::ThreatLevel::CRITICAL);
    CHECK(result.should_block);
}

// ============================================================================
// Comment bypass
// ============================================================================

TEST_CASE("Detects comment bypass after WHERE", "[sqli]") {
    SqlInjectionDetector detector;
    auto result = detector.analyze(
        "SELECT * FROM users WHERE id = 1 --AND is_admin = false",
        "SELECT * FROM users WHERE id = $1",
        make_parsed());
    CHECK(result.threat_level >= SqlInjectionDetector::ThreatLevel::MEDIUM);
}

// ============================================================================
// Stacked queries
// ============================================================================

TEST_CASE("Detects stacked queries", "[sqli]") {
    SqlInjectionDetector detector;
    auto result = detector.analyze(
        "SELECT 1; DROP TABLE users",
        "SELECT 1; DROP TABLE users",
        make_parsed());
    CHECK(result.threat_level >= SqlInjectionDetector::ThreatLevel::HIGH);
    CHECK(result.should_block);
}

// ============================================================================
// Time-based blind
// ============================================================================

TEST_CASE("Detects pg_sleep time-based blind", "[sqli]") {
    SqlInjectionDetector detector;
    auto result = detector.analyze(
        "SELECT * FROM users WHERE id = 1 AND pg_sleep(5)",
        "SELECT * FROM users WHERE id = $1 AND pg_sleep(5)",
        make_parsed());
    CHECK(result.threat_level >= SqlInjectionDetector::ThreatLevel::HIGH);
    CHECK(result.should_block);
}

// ============================================================================
// Error-based
// ============================================================================

TEST_CASE("Detects error-based extractvalue injection", "[sqli]") {
    SqlInjectionDetector detector;
    auto result = detector.analyze(
        "SELECT extractvalue(1, concat(0x7e, (SELECT version())))",
        "SELECT extractvalue(1, concat(0x7e, (SELECT version())))",
        make_parsed());
    CHECK(result.threat_level >= SqlInjectionDetector::ThreatLevel::MEDIUM);
}

// ============================================================================
// Disabled detector
// ============================================================================

TEST_CASE("Disabled detector passes everything", "[sqli]") {
    SqlInjectionDetector::Config cfg;
    cfg.enabled = false;
    SqlInjectionDetector detector(cfg);

    auto result = detector.analyze(
        "SELECT * FROM users WHERE 1=1; DROP TABLE users",
        "SELECT * FROM users WHERE 1=1; DROP TABLE users",
        make_parsed());
    CHECK(result.threat_level == SqlInjectionDetector::ThreatLevel::NONE);
    CHECK_FALSE(result.should_block);
}

// ============================================================================
// threat_level_to_string
// ============================================================================

TEST_CASE("threat_level_to_string returns correct strings", "[sqli]") {
    CHECK(std::string(SqlInjectionDetector::threat_level_to_string(
        SqlInjectionDetector::ThreatLevel::NONE)) == "NONE");
    CHECK(std::string(SqlInjectionDetector::threat_level_to_string(
        SqlInjectionDetector::ThreatLevel::CRITICAL)) == "CRITICAL");
}
