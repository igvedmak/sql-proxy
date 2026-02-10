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

// ============================================================================
// Case-insensitive comparison helpers (allocation-free)
// ============================================================================

inline char fast_lower(unsigned char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : static_cast<char>(c);
}

// Case-insensitive string equality (no allocation)
inline bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (fast_lower(static_cast<unsigned char>(a[i])) !=
            fast_lower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

// Case-insensitive substring search (no allocation)
// Assumes needle is already lowercase.
inline bool icontains(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) return true;
    if (haystack.size() < needle.size()) return false;
    const size_t limit = haystack.size() - needle.size();
    for (size_t i = 0; i <= limit; ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            if (fast_lower(static_cast<unsigned char>(haystack[i + j])) != needle[j]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

// ============================================================================
// Validation functions (allocation-free where possible)
// ============================================================================

bool luhn_validate(std::string_view number) {
    // Count digits first (no allocation)
    int digit_count = 0;
    for (const char c : number) {
        if (c >= '0' && c <= '9') ++digit_count;
    }
    if (digit_count < 13 || digit_count > 19) return false;

    int sum = 0;
    bool double_digit = false;

    // Process from right to left, skipping non-digits (no allocation)
    for (int i = static_cast<int>(number.size()) - 1; i >= 0; --i) {
        if (number[i] < '0' || number[i] > '9') continue;
        int digit = number[i] - '0';
        if (double_digit) {
            digit *= 2;
            if (digit > 9) digit -= 9;
        }
        sum += digit;
        double_digit = !double_digit;
    }

    return (sum % 10) == 0;
}

bool validate_ssn(std::string_view value) {
    // Extract exactly 9 digits in-place (no allocation — stack array)
    char digits[9];
    int count = 0;
    for (const char c : value) {
        if (c >= '0' && c <= '9') {
            if (count >= 9) return false;
            digits[count++] = c;
        }
    }
    if (count != 9) return false;

    const int area = (digits[0] - '0') * 100 + (digits[1] - '0') * 10 + (digits[2] - '0');
    if (area == 0 || area == 666 || area >= 900) return false;
    const int group = (digits[3] - '0') * 10 + (digits[4] - '0');
    if (group == 0) return false;
    const int serial = (digits[5] - '0') * 1000 + (digits[6] - '0') * 100
                     + (digits[7] - '0') * 10 + (digits[8] - '0');
    if (serial == 0) return false;
    return true;
}

bool looks_like_email(std::string_view value) {
    const auto at_pos = value.find('@');
    if (at_pos == std::string_view::npos || at_pos == 0 || at_pos >= value.size() - 1)
        return false;

    for (size_t i = 0; i < at_pos; ++i) {
        const auto c = static_cast<unsigned char>(value[i]);
        if (!std::isalnum(c) && c != '.' && c != '_' && c != '%' && c != '+' && c != '-')
            return false;
    }

    const auto domain = value.substr(at_pos + 1);
    const auto last_dot = domain.rfind('.');
    if (last_dot == std::string_view::npos || last_dot == 0 || last_dot >= domain.size() - 1)
        return false;

    const auto tld = domain.substr(last_dot + 1);
    if (tld.size() < 2 || tld.size() > 8) return false;
    for (const auto c : tld) {
        if (!std::isalpha(static_cast<unsigned char>(c))) return false;
    }

    for (size_t i = 0; i < last_dot; ++i) {
        const auto c = static_cast<unsigned char>(domain[i]);
        if (!std::isalnum(c) && c != '.' && c != '-') return false;
    }

    return true;
}

bool looks_like_phone(std::string_view value) {
    int digits = 0;
    for (const char c : value) {
        if (c >= '0' && c <= '9') {
            ++digits;
        } else if (c != '-' && c != '.' && c != ' ' && c != '(' && c != ')' && c != '+') {
            return false;
        }
    }
    return digits >= 10 && digits <= 11;
}

bool looks_like_ssn(std::string_view value) {
    int digits = 0;
    for (const char c : value) {
        if (c >= '0' && c <= '9') {
            ++digits;
        } else if (c != '-' && c != ' ') {
            return false;
        }
    }
    return digits == 9;
}

bool looks_like_credit_card(std::string_view value) {
    int digits = 0;
    for (const char c : value) {
        if (c >= '0' && c <= '9') {
            ++digits;
        } else if (c != '-' && c != ' ') {
            return false;
        }
    }
    return digits >= 13 && digits <= 19;
}

} // anonymous namespace

ClassifierRegistry::ClassifierRegistry() {
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

        // Skip derived columns (will handle in Phase 2)
        if (derived_names.count(col_name) > 0) continue;

        // Strategy 1: Column name matching (allocation-free)
        const auto name_type = classify_by_name(col_name);
        if (name_type.has_value()) {
            base_classifications[col_name] = *name_type;
            classification_result.classifications[col_name] =
                ColumnClassification(col_name, *name_type, 0.9, "ColumnName");
            continue;
        }

        // Strategy 2: Type OID hint (if available)
        if (i < result.column_type_oids.size() && result.column_type_oids[i] != 0) {
            const auto oid_type = classify_by_type_oid(col_name, result.column_type_oids[i]);
            if (oid_type.has_value()) {
                base_classifications[col_name] = *oid_type;
                classification_result.classifications[col_name] =
                    ColumnClassification(col_name, *oid_type, 0.85, "TypeOid");
                continue;
            }
        }

        // Strategy 3: Pattern matching directly on result rows (no vector copy)
        const auto pattern_type = classify_by_pattern(result, i);
        if (pattern_type.has_value()) {
            base_classifications[col_name] = *pattern_type;
            classification_result.classifications[col_name] =
                ColumnClassification(col_name, *pattern_type, 0.8, "RegexValue");
        }
    }

    // Phase 2: Classify derived columns (inherit PII from source columns)
    for (const auto& proj : analysis.projections) {
        if (proj.derived_from.empty()) continue;

        const auto derived_cls = classify_derived_column(proj, base_classifications);
        if (derived_cls.has_value()) {
            classification_result.classifications[proj.name] = *derived_cls;
        }
    }

    return classification_result;
}

std::optional<ClassificationType> ClassifierRegistry::classify_by_name(std::string_view col_name) const {
    // Exact match (case-insensitive, no allocation)
    for (const auto& [pattern, type] : column_patterns_) {
        if (iequals(col_name, pattern)) {
            return type;
        }
    }

    // Substring match (case-insensitive, no allocation)
    for (const auto& [pattern, type] : column_patterns_) {
        if (col_name.size() > pattern.size() && icontains(col_name, pattern)) {
            return type;
        }
    }

    return std::nullopt;
}

std::optional<ClassificationType> ClassifierRegistry::classify_by_pattern(
    const QueryResult& result,
    size_t col_index) const {

    if (result.rows.empty()) {
        return std::nullopt;
    }

    const size_t sample_size = std::min<size_t>(20, result.rows.size());

    int email_matches = 0;
    int phone_matches = 0;
    int ssn_matches = 0;
    int cc_matches = 0;

    // 50% threshold with early exit
    const int threshold = static_cast<int>((sample_size + 1) / 2);

    for (size_t row = 0; row < sample_size; ++row) {
        if (col_index >= result.rows[row].size()) continue;
        const std::string_view value = result.rows[row][col_index];

        // Check each pattern; early return when threshold reached
        if (looks_like_credit_card(value) && luhn_validate(value)) {
            if (++cc_matches >= threshold) return ClassificationType::PII_CREDIT_CARD;
        }
        if (looks_like_ssn(value) && validate_ssn(value)) {
            if (++ssn_matches >= threshold) return ClassificationType::PII_SSN;
        }
        if (looks_like_email(value)) {
            if (++email_matches >= threshold) return ClassificationType::PII_EMAIL;
        }
        if (looks_like_phone(value)) {
            if (++phone_matches >= threshold) return ClassificationType::PII_PHONE;
        }
    }

    // Final check (for cases where threshold wasn't reached mid-loop)
    if (cc_matches >= threshold) return ClassificationType::PII_CREDIT_CARD;
    if (ssn_matches >= threshold) return ClassificationType::PII_SSN;
    if (email_matches >= threshold) return ClassificationType::PII_EMAIL;
    if (phone_matches >= threshold) return ClassificationType::PII_PHONE;

    return std::nullopt;
}

std::optional<ClassificationType> ClassifierRegistry::classify_by_type_oid(
    std::string_view col_name,
    uint32_t type_oid) {

    constexpr uint32_t TEXTOID = 25;
    constexpr uint32_t VARCHAROID = 1043;
    constexpr uint32_t BPCHAROID = 1042;
    constexpr uint32_t INT8OID = 20;
    constexpr uint32_t INT4OID = 23;

    const bool is_text = (type_oid == TEXTOID || type_oid == VARCHAROID || type_oid == BPCHAROID);
    const bool is_numeric = (type_oid == INT4OID || type_oid == INT8OID);

    if (is_text && (icontains(col_name, "email") || icontains(col_name, "mail"))) {
        return ClassificationType::PII_EMAIL;
    }
    if ((is_text || is_numeric) && (icontains(col_name, "ssn") || icontains(col_name, "social_security"))) {
        return ClassificationType::PII_SSN;
    }
    if ((is_text || type_oid == INT8OID) && (icontains(col_name, "phone") || icontains(col_name, "mobile") || icontains(col_name, "telephone"))) {
        return ClassificationType::PII_PHONE;
    }
    if ((is_text || type_oid == INT8OID) && (icontains(col_name, "credit_card") || icontains(col_name, "card_number"))) {
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

    const std::string expr = utils::to_lower(projection.expression);

    static const std::array<std::string_view, 14> destroyers = {{
        "length(", "char_length(", "octet_length(",
        "md5(", "sha", "crypt(",
        "count(", "sum(", "avg(", "min(", "max(",
        "extract(", "date_part(", "date_trunc("
    }};

    for (const auto func : destroyers) {
        if (expr.contains(func)) {
            return std::nullopt;
        }
    }

    return ColumnClassification(projection.name, pii_type, 0.9, "DerivedColumn");
}

} // namespace sqlproxy
