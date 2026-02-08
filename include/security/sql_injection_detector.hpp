#pragma once

#include "core/types.hpp"
#include <string>
#include <vector>

namespace sqlproxy {

class SqlInjectionDetector {
public:
    enum class ThreatLevel { NONE, LOW, MEDIUM, HIGH, CRITICAL };

    struct DetectionResult {
        ThreatLevel threat_level = ThreatLevel::NONE;
        std::vector<std::string> patterns_matched;
        std::string description;
        bool should_block = false;
    };

    struct Config {
        bool enabled = true;
        ThreatLevel block_threshold = ThreatLevel::HIGH;
    };

    SqlInjectionDetector() : SqlInjectionDetector(Config{}) {}
    explicit SqlInjectionDetector(const Config& config);

    [[nodiscard]] DetectionResult analyze(
        const std::string& raw_sql,
        const std::string& normalized_sql,
        const ParsedQuery& parsed) const;

    [[nodiscard]] static const char* threat_level_to_string(ThreatLevel level);

private:
    void check_tautologies(const std::string& sql, DetectionResult& result) const;
    void check_union_injection(const std::string& sql, const ParsedQuery& parsed,
                               DetectionResult& result) const;
    void check_comment_bypass(const std::string& raw_sql, DetectionResult& result) const;
    void check_stacked_queries(const std::string& raw_sql, DetectionResult& result) const;
    void check_time_based_blind(const std::string& sql, DetectionResult& result) const;
    void check_error_based(const std::string& sql, DetectionResult& result) const;

    void elevate_threat(DetectionResult& result, ThreatLevel level) const;

    Config config_;
};

} // namespace sqlproxy
