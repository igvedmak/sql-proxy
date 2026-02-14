#pragma once

#include "security/compliance_reporter.hpp"
#include "security/lineage_tracker.hpp"
#include "audit/audit_emitter.hpp"
#include <string>
#include <memory>

namespace sqlproxy {

// Forward declarations
class DataCatalog;

enum class ReportType { SOC2, GDPR, HIPAA };

struct ReportOptions {
    ReportType type = ReportType::SOC2;
    bool html = true;  // false = JSON
};

class ReportGenerator {
public:
    ReportGenerator(
        std::shared_ptr<ComplianceReporter> compliance,
        std::shared_ptr<LineageTracker> lineage,
        std::shared_ptr<AuditEmitter> audit,
        std::shared_ptr<DataCatalog> catalog = nullptr);

    [[nodiscard]] std::string generate(const ReportOptions& opts) const;

private:
    std::shared_ptr<ComplianceReporter> compliance_;
    std::shared_ptr<LineageTracker> lineage_;
    std::shared_ptr<AuditEmitter> audit_;
    std::shared_ptr<DataCatalog> catalog_;

    [[nodiscard]] std::string section_header(const ReportOptions& opts) const;
    [[nodiscard]] std::string section_executive_summary(
        const SecuritySummary& sec, const PiiAccessReport& pii) const;
    [[nodiscard]] std::string section_pii_inventory(const PiiAccessReport& pii) const;
    [[nodiscard]] std::string section_access_controls(
        const std::vector<LineageSummary>& summaries) const;
    [[nodiscard]] std::string section_security_events(const SecuritySummary& sec) const;
    [[nodiscard]] std::string section_masking_coverage(const PiiAccessReport& pii) const;
    [[nodiscard]] std::string section_audit_integrity() const;
    [[nodiscard]] std::string section_footer() const;
    [[nodiscard]] std::string generate_json(const ReportOptions& opts) const;
};

} // namespace sqlproxy
