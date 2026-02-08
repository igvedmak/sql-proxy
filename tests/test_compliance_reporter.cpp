#include <catch2/catch_test_macros.hpp>
#include "security/compliance_reporter.hpp"
#include "security/lineage_tracker.hpp"
#include "security/anomaly_detector.hpp"
#include "audit/audit_emitter.hpp"

using namespace sqlproxy;

static LineageEvent make_event(const std::string& user, const std::string& table,
                               const std::string& column, const std::string& classification,
                               bool was_masked = false) {
    LineageEvent e;
    e.timestamp = "2026-01-01T00:00:00.000Z";
    e.user = user;
    e.database = "testdb";
    e.table = table;
    e.column = column;
    e.classification = classification;
    e.access_type = "SELECT";
    e.was_masked = was_masked;
    e.masking_action = was_masked ? "PARTIAL" : "";
    return e;
}

// ============================================================================
// PII Report generation
// ============================================================================

TEST_CASE("PII report with lineage data", "[compliance]") {
    auto lineage = std::make_shared<LineageTracker>();
    auto anomaly = std::make_shared<AnomalyDetector>();
    auto audit = std::make_shared<AuditEmitter>("/dev/null");

    // Record some PII accesses
    lineage->record(make_event("alice", "customers", "email", "PII.Email", true));
    lineage->record(make_event("alice", "customers", "email", "PII.Email", false));
    lineage->record(make_event("bob", "customers", "phone", "PII.Phone", true));

    ComplianceReporter reporter(lineage, anomaly, audit);
    auto report = reporter.generate_pii_report();

    CHECK(report.total_pii_accesses == 3);
    CHECK(report.total_masked == 2);
    CHECK(report.masking_coverage_pct > 60.0);
    CHECK(report.masking_coverage_pct < 70.0);  // 2/3 ≈ 66.7%
    CHECK(report.entries.size() == 2);  // 2 unique column keys
}

// ============================================================================
// PII Report with no data
// ============================================================================

TEST_CASE("PII report with no data returns empty", "[compliance]") {
    auto lineage = std::make_shared<LineageTracker>();
    auto anomaly = std::make_shared<AnomalyDetector>();
    auto audit = std::make_shared<AuditEmitter>("/dev/null");

    ComplianceReporter reporter(lineage, anomaly, audit);
    auto report = reporter.generate_pii_report();

    CHECK(report.total_pii_accesses == 0);
    CHECK(report.total_masked == 0);
    CHECK(report.masking_coverage_pct == 0.0);
    CHECK(report.entries.empty());
}

// ============================================================================
// Security Summary
// ============================================================================

TEST_CASE("Security summary aggregates stats", "[compliance]") {
    auto lineage = std::make_shared<LineageTracker>();
    auto anomaly = std::make_shared<AnomalyDetector>();
    auto audit = std::make_shared<AuditEmitter>("/dev/null");

    // Record some anomaly data
    anomaly->record("alice", {"customers"}, 100);
    anomaly->record("bob", {"orders"}, 200);

    // Record lineage
    lineage->record(make_event("alice", "customers", "email", "PII.Email", true));

    ComplianceReporter reporter(lineage, anomaly, audit);
    auto summary = reporter.generate_security_summary();

    CHECK(summary.tracked_users == 2);
    CHECK(summary.pii_accesses == 1);
    CHECK(!summary.generated_at.empty());
}

// ============================================================================
// JSON serialization
// ============================================================================

TEST_CASE("PII report JSON serialization", "[compliance]") {
    PiiAccessReport report;
    report.generated_at = "2026-01-01T00:00:00Z";
    report.period = "last_24h";
    report.total_pii_accesses = 42;
    report.total_masked = 30;
    report.masking_coverage_pct = 71.4;

    PiiAccessReport::Entry entry;
    entry.user = "alice";
    entry.table = "customers";
    entry.column = "email";
    entry.classification = "PII.Email";
    entry.access_count = 42;
    entry.masked_count = 30;
    report.entries.push_back(entry);

    auto json = ComplianceReporter::pii_report_to_json(report);
    CHECK(json.find("\"total_pii_accesses\":42") != std::string::npos);
    CHECK(json.find("\"alice\"") != std::string::npos);
    CHECK(json.find("PII.Email") != std::string::npos);
}

TEST_CASE("Security summary JSON serialization", "[compliance]") {
    SecuritySummary summary;
    summary.generated_at = "2026-01-01T00:00:00Z";
    summary.total_queries = 1000;
    summary.blocked_queries = 5;
    summary.injection_attempts = 3;
    summary.anomalies_detected = 10;
    summary.pii_accesses = 500;
    summary.masking_coverage_pct = 95.2;
    summary.rate_limited_requests = 2;
    summary.tracked_users = 4;

    auto json = ComplianceReporter::security_summary_to_json(summary);
    CHECK(json.find("\"total_queries\":1000") != std::string::npos);
    CHECK(json.find("\"injection_attempts\":3") != std::string::npos);
    CHECK(json.find("\"tracked_users\":4") != std::string::npos);
}
