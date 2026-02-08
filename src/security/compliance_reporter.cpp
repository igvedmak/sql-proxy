#include "security/compliance_reporter.hpp"

#include <chrono>
#include <format>

namespace sqlproxy {

ComplianceReporter::ComplianceReporter(
    std::shared_ptr<LineageTracker> lineage,
    std::shared_ptr<AnomalyDetector> anomaly,
    std::shared_ptr<AuditEmitter> audit)
    : lineage_(std::move(lineage)),
      anomaly_(std::move(anomaly)),
      audit_(std::move(audit)) {}

PiiAccessReport ComplianceReporter::generate_pii_report() const {
    PiiAccessReport report;

    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    struct tm tm;
    gmtime_r(&time_t, &tm);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    report.generated_at = buf;
    report.period = "all_time";

    if (!lineage_) return report;

    auto summaries = lineage_->get_summaries();
    report.entries.reserve(summaries.size());

    for (const auto& s : summaries) {
        // Parse column_key: "db.table.column"
        size_t first_dot = s.column_key.find('.');
        size_t second_dot = s.column_key.find('.', first_dot + 1);
        std::string table_name = (first_dot != std::string::npos && second_dot != std::string::npos)
            ? s.column_key.substr(first_dot + 1, second_dot - first_dot - 1)
            : "";
        std::string column_name = (second_dot != std::string::npos)
            ? s.column_key.substr(second_dot + 1)
            : s.column_key;

        // One entry per accessing user
        for (const auto& user : s.accessing_users) {
            PiiAccessReport::Entry entry;
            entry.user = user;
            entry.table = table_name;
            entry.column = column_name;
            entry.classification = s.classification;
            entry.access_count = s.total_accesses;
            entry.masked_count = s.masked_accesses;
            entry.unmasked_count = s.unmasked_accesses;

            auto last_t = std::chrono::system_clock::to_time_t(s.last_access);
            struct tm last_tm;
            gmtime_r(&last_t, &last_tm);
            strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &last_tm);
            entry.last_access = buf;

            report.entries.push_back(std::move(entry));
        }

        report.total_pii_accesses += s.total_accesses;
        report.total_masked += s.masked_accesses;
    }

    report.masking_coverage_pct = (report.total_pii_accesses > 0)
        ? (static_cast<double>(report.total_masked) / report.total_pii_accesses * 100.0)
        : 0.0;

    return report;
}

SecuritySummary ComplianceReporter::generate_security_summary() const {
    SecuritySummary summary;

    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    struct tm tm;
    gmtime_r(&time_t, &tm);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    summary.generated_at = buf;

    if (audit_) {
        auto stats = audit_->get_stats();
        summary.total_queries = stats.total_emitted;
    }

    if (lineage_) {
        summary.pii_accesses = lineage_->total_events();
    }

    if (anomaly_) {
        summary.tracked_users = anomaly_->tracked_users();
    }

    return summary;
}

std::string ComplianceReporter::pii_report_to_json(const PiiAccessReport& report) {
    std::string json = "{";
    json += std::format("\"generated_at\":\"{}\",", report.generated_at);
    json += std::format("\"period\":\"{}\",", report.period);
    json += std::format("\"total_pii_accesses\":{},", report.total_pii_accesses);
    json += std::format("\"total_masked\":{},", report.total_masked);
    json += std::format("\"masking_coverage_pct\":{:.1f},", report.masking_coverage_pct);
    json += "\"entries\":[";

    for (size_t i = 0; i < report.entries.size(); ++i) {
        if (i > 0) json += ",";
        const auto& e = report.entries[i];
        json += std::format(
            "{{\"user\":\"{}\",\"table\":\"{}\",\"column\":\"{}\","
            "\"classification\":\"{}\",\"access_count\":{},\"masked_count\":{},"
            "\"unmasked_count\":{},\"last_access\":\"{}\"}}",
            e.user, e.table, e.column, e.classification,
            e.access_count, e.masked_count, e.unmasked_count, e.last_access);
    }

    json += "]}";
    return json;
}

std::string ComplianceReporter::security_summary_to_json(const SecuritySummary& summary) {
    return std::format(
        "{{\"generated_at\":\"{}\","
        "\"total_queries\":{},"
        "\"blocked_queries\":{},"
        "\"injection_attempts\":{},"
        "\"anomalies_detected\":{},"
        "\"pii_accesses\":{},"
        "\"masking_coverage_pct\":{:.1f},"
        "\"rate_limited_requests\":{},"
        "\"tracked_users\":{}}}",
        summary.generated_at,
        summary.total_queries, summary.blocked_queries,
        summary.injection_attempts, summary.anomalies_detected,
        summary.pii_accesses, summary.masking_coverage_pct,
        summary.rate_limited_requests, summary.tracked_users);
}

} // namespace sqlproxy
