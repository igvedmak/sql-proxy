#include "security/sql_injection_detector.hpp"

#include <algorithm>
#include <cctype>
#include <utility>

namespace sqlproxy {

namespace {

// Case-insensitive substring search
bool contains_ci(std::string_view haystack, const char* needle, size_t needle_len) {
    if (needle_len > haystack.size()) return false;
    for (size_t i = 0; i <= haystack.size() - needle_len; ++i) {
        bool match = true;
        for (size_t j = 0; j < needle_len; ++j) {
            if (std::tolower(static_cast<unsigned char>(haystack[i + j])) !=
                std::tolower(static_cast<unsigned char>(needle[j]))) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

bool contains_ci(std::string_view haystack, const char* needle) {
    size_t len = 0;
    while (needle[len]) ++len;
    return contains_ci(haystack, needle, len);
}

// Check if position is inside a string literal
bool in_string_literal(std::string_view sql, size_t pos) {
    bool in_single = false;
    bool in_double = false;
    for (size_t i = 0; i < pos && i < sql.size(); ++i) {
        if (sql[i] == '\'' && !in_double) in_single = !in_single;
        if (sql[i] == '"' && !in_single) in_double = !in_double;
    }
    return in_single || in_double;
}

// Find keyword not inside string literal (case-insensitive)
size_t find_keyword(std::string_view sql, const char* keyword) {
    size_t kw_len = 0;
    while (keyword[kw_len]) ++kw_len;

    if (kw_len > sql.size()) return std::string::npos;

    for (size_t i = 0; i <= sql.size() - kw_len; ++i) {
        bool match = true;
        for (size_t j = 0; j < kw_len; ++j) {
            if (std::tolower(static_cast<unsigned char>(sql[i + j])) !=
                std::tolower(static_cast<unsigned char>(keyword[j]))) {
                match = false;
                break;
            }
        }
        if (match) {
            // Check word boundary before
            if (i > 0 && std::isalnum(static_cast<unsigned char>(sql[i - 1]))) continue;
            // Check word boundary after
            const size_t after = i + kw_len;
            if (after < sql.size() && std::isalnum(static_cast<unsigned char>(sql[after]))) continue;
            if (!in_string_literal(sql, i)) return i;
        }
    }
    return std::string::npos;
}

// Strip all block comments (/* ... */) from SQL, preserving string literals
std::string strip_block_comments(std::string_view sql) {
    std::string result;
    result.reserve(sql.size());
    bool in_single = false;
    bool in_double = false;

    for (size_t i = 0; i < sql.size(); ++i) {
        if (sql[i] == '\'' && !in_double) {
            in_single = !in_single;
            result += sql[i];
        } else if (sql[i] == '"' && !in_single) {
            in_double = !in_double;
            result += sql[i];
        } else if (!in_single && !in_double &&
                   sql[i] == '/' && i + 1 < sql.size() && sql[i + 1] == '*') {
            const size_t end = sql.find("*/", i + 2);
            if (end != std::string::npos) {
                i = end + 1;  // Skip past */
            } else {
                break;  // Unclosed comment — skip rest
            }
        } else {
            result += sql[i];
        }
    }
    return result;
}

// Decode hex-encoded strings: 0x53454C454354 → SELECT
// Returns empty string if input is not a valid hex string
std::string decode_hex_string(std::string_view hex) {
    if (hex.size() < 4 || hex[0] != '0' || (hex[1] != 'x' && hex[1] != 'X')) return {};
    const auto digits = hex.substr(2);
    if (digits.size() % 2 != 0) return {};

    std::string result;
    result.reserve(digits.size() / 2);
    for (size_t i = 0; i < digits.size(); i += 2) {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            if (c >= 'A' && c <= 'F') return 10 + c - 'A';
            return -1;
        };
        const int hi = nibble(digits[i]);
        const int lo = nibble(digits[i + 1]);
        if (hi < 0 || lo < 0) return {};
        const auto ch = static_cast<char>((hi << 4) | lo);
        if (ch < 0x20 || ch > 0x7E) return {};  // Only printable ASCII
        result += ch;
    }
    return result;
}

// Replace all 0xHEX tokens in SQL with their decoded ASCII equivalents
std::string decode_hex_tokens(std::string_view sql) {
    std::string result;
    result.reserve(sql.size());
    bool in_single = false;
    bool in_double = false;

    for (size_t i = 0; i < sql.size(); ++i) {
        if (sql[i] == '\'' && !in_double) { in_single = !in_single; result += sql[i]; continue; }
        if (sql[i] == '"' && !in_single) { in_double = !in_double; result += sql[i]; continue; }
        if (in_single || in_double) { result += sql[i]; continue; }

        // Look for 0x prefix followed by hex digits
        if (sql[i] == '0' && i + 3 < sql.size() && (sql[i + 1] == 'x' || sql[i + 1] == 'X')) {
            size_t end = i + 2;
            while (end < sql.size()) {
                const char c = sql[end];
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
                    ++end;
                else
                    break;
            }
            if (end > i + 2 && (end - i - 2) % 2 == 0 && (end - i - 2) >= 6) {
                // At least 3 bytes (6 hex chars) — likely a string, not a number
                const auto decoded = decode_hex_string(sql.substr(i, end - i));
                if (!decoded.empty()) {
                    result += decoded;
                    i = end - 1;
                    continue;
                }
            }
        }
        result += sql[i];
    }
    return result;
}

// Normalize Unicode fullwidth characters (U+FF01..U+FF5E) to ASCII (0x21..0x7E)
// e.g., Ｓ (U+FF33) → S, ＊ (U+FF0A) → *
std::string normalize_fullwidth(std::string_view sql) {
    std::string result;
    result.reserve(sql.size());
    bool changed = false;

    for (size_t i = 0; i < sql.size(); ++i) {
        // UTF-8 fullwidth chars are 3 bytes: 0xEF 0xBC 0x81..0xEF 0xBD 0x9E
        if (i + 2 < sql.size() &&
            static_cast<unsigned char>(sql[i]) == 0xEF) {
            const auto b1 = static_cast<unsigned char>(sql[i + 1]);
            const auto b2 = static_cast<unsigned char>(sql[i + 2]);
            // U+FF01..U+FF3F: 0xEF 0xBC 0x81..0xBF (! through _)
            if (b1 == 0xBC && b2 >= 0x81 && b2 <= 0xBF) {
                result += static_cast<char>(b2 - 0x60);  // 0x81→0x21('!'), 0xBF→0x5F('_')
                i += 2;
                changed = true;
                continue;
            }
            // U+FF40..U+FF5E: 0xEF 0xBD 0x80..0x9E (` through ~)
            if (b1 == 0xBD && b2 >= 0x80 && b2 <= 0x9E) {
                result += static_cast<char>(b2 - 0x20);  // 0x80→0x60('`'), 0x9E→0x7E('~')
                i += 2;
                changed = true;
                continue;
            }
        }
        result += sql[i];
    }
    return changed ? result : std::string{sql};
}

} // anonymous namespace

SqlInjectionDetector::SqlInjectionDetector(const Config& config)
    : config_(config) {}

const char* SqlInjectionDetector::threat_level_to_string(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::NONE: return "NONE";
        case ThreatLevel::LOW: return "LOW";
        case ThreatLevel::MEDIUM: return "MEDIUM";
        case ThreatLevel::HIGH: return "HIGH";
        case ThreatLevel::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

void SqlInjectionDetector::elevate_threat(DetectionResult& result, ThreatLevel level) const {
    if (std::to_underlying(level) > std::to_underlying(result.threat_level)) {
        result.threat_level = level;
    }
    if (std::to_underlying(result.threat_level) >= std::to_underlying(config_.block_threshold)) {
        result.should_block = true;
    }
}

SqlInjectionDetector::DetectionResult SqlInjectionDetector::analyze(
    std::string_view raw_sql,
    std::string_view normalized_sql,
    const ParsedQuery& parsed) const {

    if (!config_.enabled) {
        return {};
    }

    DetectionResult result;

    check_tautologies(normalized_sql, result);
    check_union_injection(normalized_sql, parsed, result);
    check_comment_bypass(raw_sql, result);
    check_comment_keyword_split(raw_sql, result);
    check_stacked_queries(raw_sql, result);
    check_time_based_blind(normalized_sql, result);
    check_error_based(normalized_sql, result);

    // Hex encoding detection: 0x53454C454354 → SELECT
    check_hex_encoding(raw_sql, parsed, result);

    // Unicode fullwidth normalization: ＳＥＬＥＣＴ → SELECT
    check_unicode_bypass(raw_sql, parsed, result);

    // Encoding bypass detection: decode and re-check
    if (config_.encoding_detection_enabled) {
        const std::string decoded = decode_encodings(raw_sql);
        if (decoded != raw_sql) {
            check_encoding_bypass(decoded, parsed, result);
        }
    }

    // Build description
    if (!result.patterns_matched.empty()) {
        result.description = "SQL injection patterns detected: ";
        for (size_t i = 0; i < result.patterns_matched.size(); ++i) {
            if (i > 0) result.description += ", ";
            result.description += result.patterns_matched[i];
        }
    }

    return result;
}

void SqlInjectionDetector::check_tautologies(std::string_view sql,
                                             DetectionResult& result) const {
    // Check for common tautology patterns: 1=1, 'a'='a', 1<>2, OR true, OR 1
    // These are commonly injected to bypass WHERE clauses

    // Numeric tautologies: N=N patterns (outside string literals)
    static const char* numeric_tautologies[] = {
        "1=1", "2=2", "1<>2", "0=0", "1!=2"
    };
    for (const auto& pattern : numeric_tautologies) {
        if (contains_ci(sql, pattern)) {
            const size_t pos = sql.find(pattern);
            if (pos != std::string::npos && !in_string_literal(sql, pos)) {
                result.patterns_matched.push_back("TAUTOLOGY");
                elevate_threat(result, ThreatLevel::HIGH);
                return;
            }
        }
    }

    // OR true / OR false patterns
    if (find_keyword(sql, "or true") != std::string::npos ||
        find_keyword(sql, "or false") != std::string::npos) {
        result.patterns_matched.push_back("TAUTOLOGY");
        elevate_threat(result, ThreatLevel::HIGH);
        return;
    }

    // String tautologies: 'x'='x' pattern
    // Look for pattern: '<char>'='<char>' where chars match
    for (size_t i = 0; i + 5 < sql.size(); ++i) {
        if (sql[i] == '\'' && sql[i + 2] == '\'' && sql[i + 3] == '=' &&
            sql[i + 4] == '\'' && i + 6 < sql.size() && sql[i + 6] == '\'' &&
            sql[i + 1] == sql[i + 5]) {
            if (!in_string_literal(sql, i)) {
                result.patterns_matched.push_back("TAUTOLOGY");
                elevate_threat(result, ThreatLevel::HIGH);
                return;
            }
        }
    }
}

void SqlInjectionDetector::check_union_injection(std::string_view sql,
                                                 const ParsedQuery& parsed,
                                                 DetectionResult& result) const {
    // UNION-based injection is one of the most dangerous patterns
    // Detect UNION SELECT or UNION ALL SELECT

    if (find_keyword(sql, "union select") != std::string::npos ||
        find_keyword(sql, "union all select") != std::string::npos) {
        // Check if the parsed query has multiple tables that shouldn't be there
        // For a single-table query with UNION, this is suspicious
        result.patterns_matched.push_back("UNION_INJECTION");
        elevate_threat(result, ThreatLevel::CRITICAL);
    }

    (void)parsed; // AST-level detection is additional context
}

void SqlInjectionDetector::check_comment_bypass(std::string_view raw_sql,
                                                DetectionResult& result) const {
    // Comment-based injection: -- or /**/ used to truncate queries
    // Only flag if comments appear after WHERE clause or inside suspicious positions

    // Check for -- comment (not at start of line)
    for (size_t i = 1; i + 1 < raw_sql.size(); ++i) {
        if (raw_sql[i] == '-' && raw_sql[i + 1] == '-') {
            if (!in_string_literal(raw_sql, i)) {
                // Check if there's meaningful SQL before the comment
                // (-- at the very end after WHERE is suspicious)
                const auto before = raw_sql.substr(0, i);
                if (find_keyword(before, "where") != std::string::npos ||
                    find_keyword(before, "and") != std::string::npos ||
                    find_keyword(before, "or") != std::string::npos) {
                    result.patterns_matched.push_back("COMMENT_BYPASS");
                    elevate_threat(result, ThreatLevel::MEDIUM);
                    return;
                }
            }
        }
    }

    // Block comment injection: /*...*/ can bypass WAF rules
    // Only flag if there's content between SELECT/WHERE keywords
    size_t block_start = 0;
    while ((block_start = raw_sql.find("/*", block_start)) != std::string::npos) {
        if (!in_string_literal(raw_sql, block_start)) {
            const size_t block_end = raw_sql.find("*/", block_start + 2);
            if (block_end != std::string::npos) {
                // Check if the comment is between SQL keywords (obfuscation)
                const auto before = raw_sql.substr(0, block_start);
                const auto after_pos = block_end + 2;
                if (after_pos < raw_sql.size()) {
                    const auto after = raw_sql.substr(after_pos);
                    // Pattern: keyword /*...*/ keyword (e.g., UN/**/ION SE/**/LECT)
                    bool before_has_alpha = false;
                    for (auto it = before.rbegin(); it != before.rend(); ++it) {
                        if (std::isspace(static_cast<unsigned char>(*it))) continue;
                        before_has_alpha = std::isalpha(static_cast<unsigned char>(*it));
                        break;
                    }
                    bool after_has_alpha = false;
                    for (const char c : after) {
                        if (std::isspace(static_cast<unsigned char>(c))) continue;
                        after_has_alpha = std::isalpha(static_cast<unsigned char>(c));
                        break;
                    }
                    if (before_has_alpha && after_has_alpha) {
                        result.patterns_matched.push_back("COMMENT_OBFUSCATION");
                        elevate_threat(result, ThreatLevel::HIGH);
                        return;
                    }
                }
            }
        }
        block_start += 2;
    }
}

void SqlInjectionDetector::check_comment_keyword_split(std::string_view raw_sql,
                                                        DetectionResult& result) const {
    // Strip all block comments and check if dangerous multi-word keywords emerge.
    // Catches obfuscation like: UN/**/ION SE/**/LECT, DR/**/OP TA/**/BLE
    const std::string stripped = strip_block_comments(raw_sql);
    if (stripped.size() == raw_sql.size()) return;  // No comments were stripped

    static const char* dangerous_keywords[] = {
        "union select", "union all select",
        "drop table", "drop database",
        "insert into", "delete from",
        "alter table", "truncate table",
        "create table", "exec ",
    };

    for (const auto& kw : dangerous_keywords) {
        // Only flag if the keyword is found in stripped but NOT in the original
        if (find_keyword(stripped, kw) != std::string::npos &&
            find_keyword(raw_sql, kw) == std::string::npos) {
            result.patterns_matched.push_back("COMMENT_KEYWORD_SPLIT");
            elevate_threat(result, ThreatLevel::CRITICAL);
            return;
        }
    }
}

void SqlInjectionDetector::check_stacked_queries(std::string_view raw_sql,
                                                 DetectionResult& result) const {
    // Stacked queries: multiple statements separated by semicolons
    // e.g., "SELECT 1; DROP TABLE users"
    // Count semicolons outside of string literals

    int semicolon_count = 0;
    bool in_single = false;
    bool in_double = false;

    for (size_t i = 0; i < raw_sql.size(); ++i) {
        const char c = raw_sql[i];
        if (c == '\'' && !in_double) in_single = !in_single;
        else if (c == '"' && !in_single) in_double = !in_double;
        else if (c == ';' && !in_single && !in_double) {
            ++semicolon_count;
        }
    }

    if (semicolon_count > 0) {
        // Check if there's a second statement after the semicolon
        bool found_statement = false;
        for (size_t i = 0; i < raw_sql.size(); ++i) {
            const char c = raw_sql[i];
            if (c == '\'' && !in_double) in_single = !in_single;
            else if (c == '"' && !in_single) in_double = !in_double;
            else if (c == ';' && !in_single && !in_double) {
                // Check if there's meaningful content after
                for (size_t j = i + 1; j < raw_sql.size(); ++j) {
                    if (!std::isspace(static_cast<unsigned char>(raw_sql[j]))) {
                        found_statement = true;
                        break;
                    }
                }
                break;
            }
        }
        if (found_statement) {
            result.patterns_matched.push_back("STACKED_QUERIES");
            elevate_threat(result, ThreatLevel::HIGH);
        }
    }
}

void SqlInjectionDetector::check_time_based_blind(std::string_view sql,
                                                   DetectionResult& result) const {
    // Time-based blind injection: SLEEP(), pg_sleep(), WAITFOR DELAY, BENCHMARK()
    static const char* time_functions[] = {
        "pg_sleep", "sleep(", "waitfor delay", "benchmark("
    };

    for (const auto& func : time_functions) {
        if (find_keyword(sql, func) != std::string::npos) {
            result.patterns_matched.push_back("TIME_BASED_BLIND");
            elevate_threat(result, ThreatLevel::HIGH);
            return;
        }
    }
}

void SqlInjectionDetector::check_error_based(std::string_view sql,
                                             DetectionResult& result) const {
    // Error-based injection: functions used to extract data via error messages
    static const char* error_functions[] = {
        "extractvalue(", "updatexml(", "xmltype(",
        "exp(~", "geometrycollection("
    };

    for (const auto& func : error_functions) {
        if (contains_ci(sql, func)) {
            size_t pos = sql.find(func);
            if (pos == std::string::npos) {
                // Try case-insensitive find
                std::string lower_sql{sql};
                std::transform(lower_sql.begin(), lower_sql.end(), lower_sql.begin(),
                    [](unsigned char c) { return std::tolower(c); });
                pos = lower_sql.find(func);
            }
            if (pos != std::string::npos && !in_string_literal(sql, pos)) {
                result.patterns_matched.push_back("ERROR_BASED");
                elevate_threat(result, ThreatLevel::MEDIUM);
                return;
            }
        }
    }
}

// Shared keyword list for encoding bypass checks
static constexpr const char* kDangerousKeywords[] = {
    "union select", "union all select",
    "drop table", "drop database",
    "insert into", "delete from",
    "alter table", "truncate table",
    "select ", "exec ",
};

void SqlInjectionDetector::check_hex_encoding(std::string_view raw_sql,
                                                const ParsedQuery& parsed,
                                                DetectionResult& result) const {
    const std::string decoded = decode_hex_tokens(raw_sql);
    if (decoded.size() == raw_sql.size() && decoded == raw_sql) return;

    for (const auto& kw : kDangerousKeywords) {
        if (find_keyword(decoded, kw) != std::string::npos &&
            find_keyword(raw_sql, kw) == std::string::npos) {
            result.patterns_matched.push_back("HEX_ENCODING_BYPASS");
            elevate_threat(result, ThreatLevel::CRITICAL);
            return;
        }
    }

    check_tautologies(decoded, result);
    check_union_injection(decoded, parsed, result);
    check_stacked_queries(decoded, result);
}

void SqlInjectionDetector::check_unicode_bypass(std::string_view raw_sql,
                                                  const ParsedQuery& parsed,
                                                  DetectionResult& result) const {
    const std::string normalized = normalize_fullwidth(raw_sql);
    if (normalized == raw_sql) return;

    for (const auto& kw : kDangerousKeywords) {
        if (find_keyword(normalized, kw) != std::string::npos) {
            result.patterns_matched.push_back("UNICODE_FULLWIDTH_BYPASS");
            elevate_threat(result, ThreatLevel::CRITICAL);
            return;
        }
    }

    check_tautologies(normalized, result);
    check_union_injection(normalized, parsed, result);
    check_stacked_queries(normalized, result);
}

std::string SqlInjectionDetector::decode_encodings(std::string_view sql) const {
    std::string result;
    result.reserve(sql.size());

    auto hex_val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        return -1;
    };

    for (size_t i = 0; i < sql.size(); ++i) {
        // URL decode: %XX
        if (sql[i] == '%' && i + 2 < sql.size()) {
            const int h = hex_val(sql[i + 1]);
            const int l = hex_val(sql[i + 2]);
            if (h >= 0 && l >= 0) {
                result += static_cast<char>((h << 4) | l);
                i += 2;
                continue;
            }
        }
        // HTML numeric entity: &#NN; or &#xHH;
        if (sql[i] == '&' && i + 2 < sql.size() && sql[i + 1] == '#') {
            size_t j = i + 2;
            bool is_hex = false;
            if (j < sql.size() && (sql[j] == 'x' || sql[j] == 'X')) {
                is_hex = true;
                ++j;
            }
            size_t start = j;
            int val = 0;
            while (j < sql.size() && j < start + 4) {
                if (is_hex) {
                    const int d = hex_val(sql[j]);
                    if (d < 0) break;
                    val = val * 16 + d;
                } else {
                    if (sql[j] < '0' || sql[j] > '9') break;
                    val = val * 10 + (sql[j] - '0');
                }
                ++j;
            }
            if (j > start && j < sql.size() && sql[j] == ';' && val > 0 && val < 128) {
                result += static_cast<char>(val);
                i = j;
                continue;
            }
        }
        // HTML named entities
        if (sql[i] == '&') {
            struct Entity { const char* name; size_t len; char ch; };
            static const Entity entities[] = {
                {"&lt;", 4, '<'}, {"&gt;", 4, '>'},
                {"&amp;", 5, '&'}, {"&quot;", 6, '"'}, {"&apos;", 6, '\''},
            };
            bool matched = false;
            for (const auto& e : entities) {
                if (i + e.len <= sql.size() && sql.substr(i, e.len) == e.name) {
                    result += e.ch;
                    i += e.len - 1;
                    matched = true;
                    break;
                }
            }
            if (matched) continue;
        }
        result += sql[i];
    }

    // Second pass: decode again (double-encoding like %2531 → %31 → 1)
    if (result != sql) {
        std::string second;
        second.reserve(result.size());
        for (size_t i = 0; i < result.size(); ++i) {
            if (result[i] == '%' && i + 2 < result.size()) {
                const int h = hex_val(result[i + 1]);
                const int l = hex_val(result[i + 2]);
                if (h >= 0 && l >= 0) {
                    second += static_cast<char>((h << 4) | l);
                    i += 2;
                    continue;
                }
            }
            second += result[i];
        }
        return second;
    }
    return result;
}

void SqlInjectionDetector::check_encoding_bypass(std::string_view decoded,
    const ParsedQuery& parsed, DetectionResult& result) const {

    // The fact that decoded differs from raw is suspicious — flag it
    result.patterns_matched.push_back("ENCODING_BYPASS");
    elevate_threat(result, ThreatLevel::MEDIUM);

    // Re-run all 6 checks on the decoded version to catch hidden attacks
    check_tautologies(decoded, result);
    check_union_injection(decoded, parsed, result);
    check_comment_bypass(decoded, result);
    check_stacked_queries(decoded, result);
    check_time_based_blind(decoded, result);
    check_error_based(decoded, result);
}

} // namespace sqlproxy
