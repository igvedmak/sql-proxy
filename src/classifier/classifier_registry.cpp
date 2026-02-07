#include "classifier/classifier_registry.hpp"
#include "core/utils.hpp"
#include <array>
#include <algorithm>
#include <numeric>
#include <cctype>
#include <string_view>
#include <unordered_set>

namespace sqlproxy {

namespace {

/**
 * @brief Luhn algorithm validation for credit card numbers
 * Reduces false positive rate from ~10% to <0.1%
 * @param number String containing only digits
 * @return true if passes Luhn check
 */
bool luhn_validate(std::string_view number) {
    // Extract digits only
    std::string digits;
    digits.reserve(number.size());
    for (char c : number) {
        if (std::isdigit(static_cast<unsigned char>(c))) {
            digits += c;
        }
    }

    if (digits.size() < 13 || digits.size() > 19) {
        return false;
    }

    int sum = 0;
    bool double_digit = false;

    // Process from right to left
    for (int i = static_cast<int>(digits.size()) - 1; i >= 0; --i) {
        int digit = digits[i] - '0';

        if (double_digit) {
            digit *= 2;
            if (digit > 9) {
                digit -= 9;
            }
        }

        sum += digit;
        double_digit = !double_digit;
    }

    return (sum % 10) == 0;
}

/**
 * @brief Validate SSN is not obviously fake
 * SSN cannot start with 000, 666, or 900-999
 */
bool validate_ssn(std::string_view value) {
    std::string digits;
    digits.reserve(9);
    for (char c : value) {
        if (std::isdigit(static_cast<unsigned char>(c))) {
            digits += c;
        }
    }

    if (digits.size() != 9) {
        return false;
    }

    // Area number (first 3) cannot be 000, 666, or 900-999
    // Use char arithmetic instead of stoi(substr()) to avoid 3 string allocations
    const int area = (digits[0] - '0') * 100 + (digits[1] - '0') * 10 + (digits[2] - '0');
    if (area == 0 || area == 666 || area >= 900) return false;

    // Group number (middle 2) cannot be 00
    const int group = (digits[3] - '0') * 10 + (digits[4] - '0');
    if (group == 0) return false;

    // Serial number (last 4) cannot be 0000
    const int serial = (digits[5] - '0') * 1000 + (digits[6] - '0') * 100
                     + (digits[7] - '0') * 10 + (digits[8] - '0');
    if (serial == 0) return false;

    return true;
}

/**
 * @brief Fast email detection — single-pass O(n) character scan
 * Replaces std::regex which is ~50-100x slower
 * Pattern: [alnum._%+-]+@[alnum.-]+\.[alpha]{2,8}
 */
bool looks_like_email(std::string_view value) {
    const auto at_pos = value.find('@');
    if (at_pos == std::string_view::npos || at_pos == 0 || at_pos >= value.size() - 1)
        return false;

    // Local part: alphanumeric + ._%+-
    for (size_t i = 0; i < at_pos; ++i) {
        const auto c = static_cast<unsigned char>(value[i]);
        if (!std::isalnum(c) && c != '.' && c != '_' && c != '%' && c != '+' && c != '-')
            return false;
    }

    // Domain: must have at least one dot after @
    const auto domain = value.substr(at_pos + 1);
    const auto last_dot = domain.rfind('.');
    if (last_dot == std::string_view::npos || last_dot == 0 || last_dot >= domain.size() - 1)
        return false;

    // TLD: 2-8 alpha characters
    const auto tld = domain.substr(last_dot + 1);
    if (tld.size() < 2 || tld.size() > 8) return false;
    for (const auto c : tld) {
        if (!std::isalpha(static_cast<unsigned char>(c))) return false;
    }

    // Domain part before TLD: alphanumeric + .-
    for (size_t i = 0; i < last_dot; ++i) {
        const auto c = static_cast<unsigned char>(domain[i]);
        if (!std::isalnum(c) && c != '.' && c != '-') return false;
    }

    return true;
}

/**
 * @brief Fast phone number detection — count digits, check separators
 * Pattern: optional +1, 10-11 digits with ()-.space separators
 */
bool looks_like_phone(std::string_view value) {
    int digits = 0;
    for (const char c : value) {
        if (std::isdigit(static_cast<unsigned char>(c))) {
            ++digits;
        } else if (c != '-' && c != '.' && c != ' ' && c != '(' && c != ')' && c != '+') {
            return false; // Invalid character for phone number
        }
    }
    return digits >= 10 && digits <= 11;
}

/**
 * @brief Fast SSN detection — exactly 9 digits with optional -/space separators
 * Pattern: NNN[-\s]?NN[-\s]?NNNN
 */
bool looks_like_ssn(std::string_view value) {
    int digits = 0;
    for (const char c : value) {
        if (std::isdigit(static_cast<unsigned char>(c))) {
            ++digits;
        } else if (c != '-' && c != ' ') {
            return false;
        }
    }
    return digits == 9;
}

/**
 * @brief Fast credit card detection — 13-19 digits with optional -/space separators
 * Pattern: groups of digits with optional separators
 */
bool looks_like_credit_card(std::string_view value) {
    int digits = 0;
    for (const char c : value) {
        if (std::isdigit(static_cast<unsigned char>(c))) {
            ++digits;
        } else if (c != '-' && c != ' ') {
            return false;
        }
    }
    return digits >= 13 && digits <= 19;
}

} // anonymous namespace

ClassifierRegistry::ClassifierRegistry() {
    // Initialize column name patterns
    column_patterns_["email"] = ClassificationType::PII_EMAIL;
    column_patterns_["e_mail"] = ClassificationType::PII_EMAIL;
    column_patterns_["mail"] = ClassificationType::PII_EMAIL;
    column_patterns_["email_address"] = ClassificationType::PII_EMAIL;

    column_patterns_["phone"] = ClassificationType::PII_PHONE;
    column_patterns_["telephone"] = ClassificationType::PII_PHONE;
    column_patterns_["mobile"] = ClassificationType::PII_PHONE;
    column_patterns_["cell"] = ClassificationType::PII_PHONE;
    column_patterns_["phone_number"] = ClassificationType::PII_PHONE;

    column_patterns_["ssn"] = ClassificationType::PII_SSN;
    column_patterns_["social_security"] = ClassificationType::PII_SSN;
    column_patterns_["social_security_number"] = ClassificationType::PII_SSN;

    column_patterns_["credit_card"] = ClassificationType::PII_CREDIT_CARD;
    column_patterns_["card_number"] = ClassificationType::PII_CREDIT_CARD;
    column_patterns_["cc_number"] = ClassificationType::PII_CREDIT_CARD;
    column_patterns_["creditcard"] = ClassificationType::PII_CREDIT_CARD;

    column_patterns_["salary"] = ClassificationType::SENSITIVE_SALARY;
    column_patterns_["compensation"] = ClassificationType::SENSITIVE_SALARY;
    column_patterns_["pay"] = ClassificationType::SENSITIVE_SALARY;
    column_patterns_["wage"] = ClassificationType::SENSITIVE_SALARY;

    column_patterns_["password"] = ClassificationType::SENSITIVE_PASSWORD;
    column_patterns_["pwd"] = ClassificationType::SENSITIVE_PASSWORD;
    column_patterns_["pass_hash"] = ClassificationType::SENSITIVE_PASSWORD;

}

ClassificationResult ClassifierRegistry::classify(
    const QueryResult& result,
    const AnalysisResult& analysis) const {

    ClassificationResult classification_result;

    if (!result.success || result.column_names.empty()) {
        return classification_result;
    }

    // Pre-compute derived column names for O(1) lookup instead of O(N*M) inner loop
    std::unordered_set<std::string_view> derived_names;
    for (const auto& proj : analysis.projections) {
        if (!proj.derived_from.empty()) {
            derived_names.insert(proj.name);
        }
    }

    // Phase 1: Classify base columns (non-derived)
    std::unordered_map<std::string, ClassificationType> base_classifications;

    for (size_t i = 0; i < result.column_names.size(); ++i) {
        const std::string& col_name = result.column_names[i];

        // Skip derived columns (will handle in Phase 2) - O(1) lookup
        if (derived_names.count(col_name) > 0) continue;

        // Strategy 1: Column name matching
        auto name_type = classify_by_name(col_name);
        if (name_type.has_value()) {
            base_classifications[col_name] = *name_type;
            classification_result.classifications[col_name] =
                ColumnClassification(col_name, *name_type, 0.9, "ColumnName");
            continue;
        }

        // Strategy 2: Type OID hint (if available)
        if (i < result.column_type_oids.size() && result.column_type_oids[i] != 0) {
            auto oid_type = classify_by_type_oid(col_name, result.column_type_oids[i]);
            if (oid_type.has_value()) {
                base_classifications[col_name] = *oid_type;
                classification_result.classifications[col_name] =
                    ColumnClassification(col_name, *oid_type, 0.85, "TypeOid");
                continue;
            }
        }

        // Strategy 3: Pattern matching on sample values
        std::vector<std::string> sample_values;
        size_t sample_size = std::min<size_t>(20, result.rows.size());
        for (size_t row = 0; row < sample_size; ++row) {
            if (i < result.rows[row].size()) {
                sample_values.push_back(result.rows[row][i]);
            }
        }

        auto pattern_type = classify_by_pattern(col_name, sample_values);
        if (pattern_type.has_value()) {
            base_classifications[col_name] = *pattern_type;
            classification_result.classifications[col_name] =
                ColumnClassification(col_name, *pattern_type, 0.8, "RegexValue");
        }
    }

    // Phase 2: Classify derived columns (inherit PII from source columns)
    for (const auto& proj : analysis.projections) {
        if (proj.derived_from.empty()) continue;

        auto derived_cls = classify_derived_column(proj, base_classifications);
        if (derived_cls.has_value()) {
            classification_result.classifications[proj.name] = *derived_cls;
        }
    }

    return classification_result;
}

std::optional<ClassificationType> ClassifierRegistry::classify_by_name(const std::string& col_name) const {
    std::string lower = utils::to_lower(col_name);

    // Exact match
    const auto it = column_patterns_.find(lower);
    if (it != column_patterns_.end()) {
        return it->second;
    }

    // Substring match (lower confidence)
    for (const auto& [pattern, type] : column_patterns_) {
        if (lower.find(pattern) != std::string::npos) {
            return type;
        }
    }

    return std::nullopt;
}

std::optional<ClassificationType> ClassifierRegistry::classify_by_pattern(
    [[maybe_unused]] const std::string& col_name,
    const std::vector<std::string>& sample_values) const {

    if (sample_values.empty()) {
        return std::nullopt;
    }

    // Use precompiled regex patterns for performance
    int email_matches = 0;
    int phone_matches = 0;
    int ssn_matches = 0;
    int cc_matches = 0;

    for (const auto& value : sample_values) {
        if (looks_like_email(value)) {
            ++email_matches;
        }
        if (looks_like_phone(value)) {
            ++phone_matches;
        }
        // SSN: pattern match + structural validation (no 000/666/9xx area)
        if (looks_like_ssn(value) && validate_ssn(value)) {
            ++ssn_matches;
        }
        // Credit card: pattern match + Luhn algorithm validation
        if (looks_like_credit_card(value) && luhn_validate(value)) {
            ++cc_matches;
        }
    }

    // 50% match threshold with ceiling division to handle edge cases
    size_t threshold = (sample_values.size() + 1) / 2;

    // Check most specific (validated) types first to prevent false positives
    if (static_cast<size_t>(cc_matches) >= threshold) {
        return ClassificationType::PII_CREDIT_CARD;
    }
    if (static_cast<size_t>(ssn_matches) >= threshold) {
        return ClassificationType::PII_SSN;
    }
    if (static_cast<size_t>(email_matches) >= threshold) {
        return ClassificationType::PII_EMAIL;
    }
    if (static_cast<size_t>(phone_matches) >= threshold) {
        return ClassificationType::PII_PHONE;
    }

    return std::nullopt;
}

std::optional<ClassificationType> ClassifierRegistry::classify_by_type_oid(
    const std::string& col_name,
    uint32_t type_oid) {
    // Note: static method - no member access

    std::string lower = utils::to_lower(col_name);

    // PostgreSQL type OIDs (from pg_type.h)
    constexpr uint32_t TEXTOID = 25;
    constexpr uint32_t VARCHAROID = 1043;
    constexpr uint32_t BPCHAROID = 1042;
    constexpr uint32_t INT8OID = 20;
    constexpr uint32_t INT4OID = 23;

    bool is_text = (type_oid == TEXTOID || type_oid == VARCHAROID || type_oid == BPCHAROID);
    bool is_numeric = (type_oid == INT4OID || type_oid == INT8OID);

    // Email: must be text type
    if (is_text && (lower.find("email") != std::string::npos ||
                    lower.find("mail") != std::string::npos)) {
        return ClassificationType::PII_EMAIL;
    }

    // SSN: could be text (formatted) or numeric (raw)
    if ((is_text || is_numeric) &&
        (lower.find("ssn") != std::string::npos ||
         lower.find("social_security") != std::string::npos)) {
        return ClassificationType::PII_SSN;
    }

    // Phone: usually text (formatted) or bigint (raw)
    if ((is_text || type_oid == INT8OID) &&
        (lower.find("phone") != std::string::npos ||
         lower.find("mobile") != std::string::npos ||
         lower.find("telephone") != std::string::npos)) {
        return ClassificationType::PII_PHONE;
    }

    // Credit card: usually text or bigint
    if ((is_text || type_oid == INT8OID) &&
        (lower.find("credit_card") != std::string::npos ||
         lower.find("card_number") != std::string::npos)) {
        return ClassificationType::PII_CREDIT_CARD;
    }

    return std::nullopt;
}

std::optional<ColumnClassification> ClassifierRegistry::classify_derived_column(
    const ProjectionColumn& projection,
    const std::unordered_map<std::string, ClassificationType>& base_classifications) {

    if (projection.derived_from.empty()) {
        return std::nullopt;
    }

    // Check ALL source columns for PII (not just first match)
    // Example: CONCAT(first_name, ' ', email) should detect email PII
    // Find the most sensitive PII type in a single pass (no intermediate vector)
    ClassificationType pii_type = ClassificationType::NONE;
    for (const auto& source_col : projection.derived_from) {
        const auto it = base_classifications.find(source_col);
        if (it != base_classifications.end() && it->second > pii_type) {
            pii_type = it->second;
        }
    }

    if (pii_type == ClassificationType::NONE) {
        return std::nullopt;
    }

    // Analyze expression to determine if PII is preserved or destroyed
    const std::string expr = utils::to_lower(projection.expression);

    // PII-destroying functions (aggregation, hashing, length)
    // Static to avoid re-creating on every call
    static const std::array<std::string_view, 14> destroyers = {{
        "length(", "char_length(", "octet_length(",
        "md5(", "sha", "crypt(",
        "count(", "sum(", "avg(", "min(", "max(",
        "extract(", "date_part(", "date_trunc("
    }};

    for (const auto func : destroyers) {
        if (expr.find(func) != std::string::npos) {
            return std::nullopt;
        }
    }

    // PII-preserving functions (formatting, string operations)
    // These preserve PII: UPPER, LOWER, TRIM, SUBSTRING, CONCAT, etc.

    // Return classification with slightly lower confidence
    return ColumnClassification(projection.name, pii_type, 0.9, "DerivedColumn");
}

} // namespace sqlproxy
