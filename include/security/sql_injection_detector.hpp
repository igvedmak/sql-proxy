#pragma once

#include "core/types.hpp"
#include <string>
#include <string_view>
#include <vector>

namespace sqlproxy {

class SqlInjectionDetector {
public:
    // ThreatLevel is now a top-level enum in core/types.hpp; alias for backward compatibility
    using ThreatLevel = sqlproxy::ThreatLevel;

    struct DetectionResult {
        ThreatLevel threat_level = ThreatLevel::NONE;
        std::vector<std::string> patterns_matched;
        std::string description;
        bool should_block = false;
    };

    struct Config {
        bool enabled = true;
        ThreatLevel block_threshold = ThreatLevel::HIGH;
        bool encoding_detection_enabled = true;
    };

    SqlInjectionDetector() : SqlInjectionDetector(Config{}) {}
    explicit SqlInjectionDetector(const Config& config);

    [[nodiscard]] DetectionResult analyze(
        std::string_view raw_sql,
        std::string_view normalized_sql,
        const ParsedQuery& parsed) const;

    [[nodiscard]] static const char* threat_level_to_string(ThreatLevel level);

private:
    void check_tautologies(std::string_view sql, DetectionResult& result) const;
    void check_union_injection(std::string_view sql, const ParsedQuery& parsed,
                               DetectionResult& result) const;
    void check_comment_bypass(std::string_view raw_sql, DetectionResult& result) const;
    void check_stacked_queries(std::string_view raw_sql, DetectionResult& result) const;
    void check_time_based_blind(std::string_view sql, DetectionResult& result) const;
    void check_error_based(std::string_view sql, DetectionResult& result) const;
    std::string decode_encodings(std::string_view sql) const;
    void check_encoding_bypass(std::string_view raw, std::string_view decoded,
                                const ParsedQuery& parsed, DetectionResult& result) const;

    void elevate_threat(DetectionResult& result, ThreatLevel level) const;

    Config config_;
};

} // namespace sqlproxy
