#pragma once

#include "security/lineage_tracker.hpp"
#include "security/anomaly_detector.hpp"
#include "audit/audit_emitter.hpp"

#include <memory>
#include <string>
#include <vector>

namespace sqlproxy {

struct PiiAccessReport {
    struct Entry {
        std::string user;
        std::string table;
        std::string column;
        std::string classification;
        uint64_t access_count = 0;
        uint64_t masked_count = 0;
        uint64_t unmasked_count = 0;
        std::string last_access;
    };

    std::string generated_at;
    std::string period;
    std::vector<Entry> entries;
    uint64_t total_pii_accesses = 0;
    uint64_t total_masked = 0;
    double masking_coverage_pct = 0.0;
};

struct SecuritySummary {
    std::string generated_at;
    uint64_t total_queries = 0;
    uint64_t blocked_queries = 0;
    uint64_t injection_attempts = 0;
    uint64_t anomalies_detected = 0;
    uint64_t pii_accesses = 0;
    double masking_coverage_pct = 0.0;
    uint64_t rate_limited_requests = 0;
    size_t tracked_users = 0;
};

class ComplianceReporter {
public:
    ComplianceReporter(
        std::shared_ptr<LineageTracker> lineage,
        std::shared_ptr<AnomalyDetector> anomaly,
        std::shared_ptr<AuditEmitter> audit);

    [[nodiscard]] PiiAccessReport generate_pii_report() const;
    [[nodiscard]] SecuritySummary generate_security_summary() const;

    // JSON serialization
    [[nodiscard]] static std::string pii_report_to_json(const PiiAccessReport& report);
    [[nodiscard]] static std::string security_summary_to_json(const SecuritySummary& summary);

private:
    std::shared_ptr<LineageTracker> lineage_;
    std::shared_ptr<AnomalyDetector> anomaly_;
    std::shared_ptr<AuditEmitter> audit_;
};

} // namespace sqlproxy
