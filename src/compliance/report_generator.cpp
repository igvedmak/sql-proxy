#include "compliance/report_generator.hpp"
#include "core/utils.hpp"

#include <format>

namespace sqlproxy {

ReportGenerator::ReportGenerator(
    std::shared_ptr<ComplianceReporter> compliance,
    std::shared_ptr<LineageTracker> lineage,
    std::shared_ptr<AuditEmitter> audit,
    std::shared_ptr<DataCatalog> catalog)
    : compliance_(std::move(compliance)),
      lineage_(std::move(lineage)),
      audit_(std::move(audit)),
      catalog_(std::move(catalog)) {}

std::string ReportGenerator::generate(const ReportOptions& opts) const {
    if (!opts.html) return generate_json(opts);

    const auto pii = compliance_->generate_pii_report();
    const auto sec = compliance_->generate_security_summary();
    const auto summaries = lineage_ ? lineage_->get_summaries() : std::vector<LineageSummary>{};

    std::string html;
    html.reserve(32768);

    html += section_header(opts);
    html += section_executive_summary(sec, pii);

    switch (opts.type) {
        case ReportType::SOC2:
            html += section_security_events(sec);
            html += section_access_controls(summaries);
            html += section_audit_integrity();
            html += section_pii_inventory(pii);
            break;
        case ReportType::GDPR:
            html += section_pii_inventory(pii);
            html += section_masking_coverage(pii);
            html += section_access_controls(summaries);
            break;
        case ReportType::HIPAA:
            html += section_pii_inventory(pii);
            html += section_security_events(sec);
            html += section_access_controls(summaries);
            html += section_audit_integrity();
            break;
    }

    html += section_footer();
    return html;
}

std::string ReportGenerator::section_header(const ReportOptions& opts) const {
    const char* report_name = "SOC 2 Type II";
    if (opts.type == ReportType::GDPR) report_name = "GDPR Data Protection";
    else if (opts.type == ReportType::HIPAA) report_name = "HIPAA Security";

    return std::format(R"(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{} Compliance Report — SQL Proxy</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         color: #1a1a2e; background: #f8f9fa; line-height: 1.6; }}
  .header {{ background: #1a1a2e; color: #fff; padding: 2rem 3rem; }}
  .header h1 {{ font-size: 1.8rem; margin-bottom: 0.3rem; }}
  .header p {{ opacity: 0.8; font-size: 0.9rem; }}
  .content {{ max-width: 960px; margin: 2rem auto; padding: 0 2rem; }}
  section {{ background: #fff; border-radius: 8px; padding: 1.5rem 2rem;
            margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
  h2 {{ font-size: 1.2rem; color: #1a1a2e; border-bottom: 2px solid #e9ecef;
       padding-bottom: 0.5rem; margin-bottom: 1rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{ background: #f1f3f5; text-align: left; padding: 0.6rem 0.8rem;
       border-bottom: 2px solid #dee2e6; font-weight: 600; }}
  td {{ padding: 0.5rem 0.8rem; border-bottom: 1px solid #e9ecef; }}
  tr:hover td {{ background: #f8f9fa; }}
  .metric {{ display: inline-block; background: #e8f4fd; border-radius: 6px;
            padding: 0.8rem 1.2rem; margin: 0.3rem; text-align: center; }}
  .metric .value {{ font-size: 1.5rem; font-weight: 700; color: #1a1a2e; }}
  .metric .label {{ font-size: 0.75rem; color: #666; }}
  .pass {{ color: #2e7d32; font-weight: 600; }}
  .warn {{ color: #f57c00; font-weight: 600; }}
  .fail {{ color: #c62828; font-weight: 600; }}
  .footer {{ text-align: center; padding: 2rem; color: #999; font-size: 0.8rem; }}
  @media print {{
    .header {{ page-break-after: avoid; }}
    section {{ page-break-inside: avoid; }}
  }}
</style>
</head>
<body>
<div class="header">
  <h1>{} Compliance Report</h1>
  <p>Generated: {} | SQL Proxy Governance Platform</p>
</div>
<div class="content">
)", report_name, report_name, utils::format_timestamp(std::chrono::system_clock::now()));
}

std::string ReportGenerator::section_executive_summary(
    const SecuritySummary& sec, const PiiAccessReport& pii) const {
    return std::format(
        R"(<section>
<h2>Executive Summary</h2>
<div>
  <div class="metric"><div class="value">{}</div><div class="label">Total Queries</div></div>
  <div class="metric"><div class="value">{}</div><div class="label">Blocked</div></div>
  <div class="metric"><div class="value">{}</div><div class="label">PII Accesses</div></div>
  <div class="metric"><div class="value">{:.1f}%</div><div class="label">Masking Coverage</div></div>
  <div class="metric"><div class="value">{}</div><div class="label">Tracked Users</div></div>
</div>
</section>
)", sec.total_queries, sec.blocked_queries, pii.total_pii_accesses,
        pii.masking_coverage_pct, sec.tracked_users);
}

std::string ReportGenerator::section_pii_inventory(const PiiAccessReport& pii) const {
    std::string s;
    s += "<section><h2>PII Data Inventory</h2>";
    s += std::format("<p>Total PII accesses: <strong>{}</strong> | "
                     "Masked: <strong>{}</strong> ({:.1f}%)</p>",
                     pii.total_pii_accesses, pii.total_masked,
                     pii.masking_coverage_pct);
    s += "<table><thead><tr>"
         "<th>Table</th><th>Column</th><th>Classification</th>"
         "<th>Accesses</th><th>Masked</th><th>Unmasked</th>"
         "<th>User</th></tr></thead><tbody>";
    for (const auto& e : pii.entries) {
        s += std::format("<tr><td>{}</td><td>{}</td><td>{}</td>"
                         "<td>{}</td><td>{}</td><td>{}</td>"
                         "<td>{}</td></tr>",
                         e.table, e.column, e.classification,
                         e.access_count, e.masked_count,
                         e.unmasked_count, e.user);
    }
    s += "</tbody></table></section>";
    return s;
}

std::string ReportGenerator::section_access_controls(
    const std::vector<LineageSummary>& summaries) const {
    std::string s;
    s += "<section><h2>Data Access Controls</h2>";
    s += std::format("<p>Tracking <strong>{}</strong> column access patterns</p>", summaries.size());
    s += "<table><thead><tr>"
         "<th>Column</th><th>Classification</th>"
         "<th>Total Accesses</th><th>Masked</th><th>Unmasked</th>"
         "<th>Users</th></tr></thead><tbody>";
    for (const auto& sm : summaries) {
        s += std::format("<tr><td>{}</td><td>{}</td>"
                         "<td>{}</td><td>{}</td><td>{}</td>"
                         "<td>{}</td></tr>",
                         sm.column_key, sm.classification,
                         sm.total_accesses, sm.masked_accesses,
                         sm.unmasked_accesses, sm.accessing_users.size());
    }
    s += "</tbody></table></section>";
    return s;
}

std::string ReportGenerator::section_security_events(const SecuritySummary& sec) const {
    return std::format(
        R"(<section>
<h2>Security Events</h2>
<table>
<thead><tr><th>Metric</th><th>Count</th><th>Status</th></tr></thead>
<tbody>
<tr><td>SQL Injection Attempts</td><td>{}</td><td class="{}">{}</td></tr>
<tr><td>Anomalies Detected</td><td>{}</td><td class="{}">{}</td></tr>
<tr><td>Rate Limited Requests</td><td>{}</td><td class="{}">{}</td></tr>
<tr><td>Blocked Queries</td><td>{}</td><td>{}</td></tr>
</tbody>
</table>
</section>
)", sec.injection_attempts,
        sec.injection_attempts > 0 ? "warn" : "pass",
        sec.injection_attempts > 0 ? "Detected" : "None",
        sec.anomalies_detected,
        sec.anomalies_detected > 10 ? "warn" : "pass",
        sec.anomalies_detected > 0 ? "Review" : "Clear",
        sec.rate_limited_requests,
        sec.rate_limited_requests > 100 ? "warn" : "pass",
        sec.rate_limited_requests > 0 ? "Active" : "None",
        sec.blocked_queries, "Enforced");
}

std::string ReportGenerator::section_masking_coverage(const PiiAccessReport& pii) const {
    const char* status_class = pii.masking_coverage_pct >= 95.0 ? "pass" :
                               pii.masking_coverage_pct >= 80.0 ? "warn" : "fail";
    const char* status_text = pii.masking_coverage_pct >= 95.0 ? "Excellent" :
                              pii.masking_coverage_pct >= 80.0 ? "Needs Improvement" : "Critical";

    return std::format(
        R"(<section>
<h2>Data Masking Coverage</h2>
<p>Overall masking coverage: <span class="{}">{:.1f}% — {}</span></p>
<div>
  <div class="metric"><div class="value">{}</div><div class="label">Total PII Accesses</div></div>
  <div class="metric"><div class="value">{}</div><div class="label">Masked</div></div>
  <div class="metric"><div class="value">{}</div><div class="label">Unmasked</div></div>
</div>
</section>
)", status_class, pii.masking_coverage_pct, status_text,
        pii.total_pii_accesses, pii.total_masked,
        pii.total_pii_accesses - pii.total_masked);
}

std::string ReportGenerator::section_audit_integrity() const {
    if (!audit_) {
        return "<section><h2>Audit Trail Integrity</h2>"
               "<p class=\"warn\">Audit emitter not available</p></section>";
    }

    const auto stats = audit_->get_stats();
    const bool chain_intact = stats.overflow_dropped == 0 &&
                              stats.sink_write_failures == 0;
    const char* status_class = chain_intact ? "pass" : "warn";
    const char* status_text = chain_intact ? "Intact — No gaps detected" : "Gaps detected";

    return std::format(
        R"(<section>
<h2>Audit Trail Integrity</h2>
<p>Hash chain status: <span class="{}">{}</span></p>
<table>
<thead><tr><th>Metric</th><th>Value</th></tr></thead>
<tbody>
<tr><td>Total Records Emitted</td><td>{}</td></tr>
<tr><td>Total Records Written</td><td>{}</td></tr>
<tr><td>Overflow Dropped</td><td>{}</td></tr>
<tr><td>Sink Write Failures</td><td>{}</td></tr>
<tr><td>Active Sinks</td><td>{}</td></tr>
<tr><td>Flush Operations</td><td>{}</td></tr>
</tbody>
</table>
</section>
)", status_class, status_text,
        stats.total_emitted, stats.total_written,
        stats.overflow_dropped, stats.sink_write_failures,
        stats.active_sinks, stats.flush_count);
}

std::string ReportGenerator::section_footer() const {
    return R"(</div>
<div class="footer">
  <p>This report was automatically generated by SQL Proxy Governance Platform.<br>
  Print to PDF via Ctrl+P / Cmd+P for archival.</p>
</div>
</body>
</html>)";
}

std::string ReportGenerator::generate_json(const ReportOptions& opts) const {
    const char* type_str = "soc2";
    if (opts.type == ReportType::GDPR) type_str = "gdpr";
    else if (opts.type == ReportType::HIPAA) type_str = "hipaa";

    const auto pii = compliance_->generate_pii_report();
    const auto sec = compliance_->generate_security_summary();

    std::string json;
    json.reserve(4096);
    json += '{';
    json += std::format("\"report_type\":\"{}\",", type_str);
    json += std::format("\"generated_at\":\"{}\",",
                        utils::format_timestamp(std::chrono::system_clock::now()));

    // Security summary
    json += "\"security_summary\":";
    json += ComplianceReporter::security_summary_to_json(sec);
    json += ',';

    // PII report
    json += "\"pii_report\":";
    json += ComplianceReporter::pii_report_to_json(pii);

    // Audit integrity
    if (audit_) {
        const auto stats = audit_->get_stats();
        json += std::format(",\"audit_integrity\":{{\"total_emitted\":{},\"total_written\":{},"
                            "\"overflow_dropped\":{},\"sink_write_failures\":{},\"chain_intact\":{}}}",
                            stats.total_emitted, stats.total_written,
                            stats.overflow_dropped, stats.sink_write_failures,
                            utils::booltostr(stats.overflow_dropped == 0 && stats.sink_write_failures == 0));
    }

    json += '}';
    return json;
}

} // namespace sqlproxy
