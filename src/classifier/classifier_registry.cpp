#include "classifier/classifier_registry.hpp"
#include "core/utils.hpp"
#include <regex>
#include <algorithm>
#include <numeric>
#include <cctype>

namespace sqlproxy {

namespace {

/**
 * @brief Luhn algorithm validation for credit card numbers
 * Reduces false positive rate from ~10% to <0.1%
 * @param number String containing only digits
 * @return true if passes Luhn check
 */
bool luhn_validate(const std::string& number) {
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
bool validate_ssn(const std::string& value) {
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
    int area = std::stoi(digits.substr(0, 3));
    if (area == 0 || area == 666 || area >= 900) {
        return false;
    }

    // Group number (middle 2) cannot be 00
    int group = std::stoi(digits.substr(3, 2));
    if (group == 0) {
        return false;
    }

    // Serial number (last 4) cannot be 0000
    int serial = std::stoi(digits.substr(5, 4));
    if (serial == 0) {
        return false;
    }

    return true;
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

    // Compile regex patterns once for performance (10-50x faster than recompiling)
    // Tightened patterns to reduce false positives:

    // Email: No double dots, proper local part and domain structure
    email_regex_ = std::regex(
        R"([a-zA-Z0-9](?:[a-zA-Z0-9._%+-]*[a-zA-Z0-9])?@[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,8})");

    // Phone: US/international format, 10-15 digits total
    phone_regex_ = std::regex(
        R"(\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4})");

    // SSN: hyphenated, spaced, or raw 9-digit format
    ssn_regex_ = std::regex(
        R"(\d{3}[-\s]?\d{2}[-\s]?\d{4})");

    // Credit card: 13-19 digits with optional separators (Luhn validated separately)
    credit_card_regex_ = std::regex(
        R"(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,7})");
}

ClassificationResult ClassifierRegistry::classify(
    const QueryResult& result,
    const AnalysisResult& analysis) {

    ClassificationResult classification_result;

    if (!result.success || result.column_names.empty()) {
        return classification_result;
    }

    // Phase 1: Classify base columns (non-derived)
    std::unordered_map<std::string, ClassificationType> base_classifications;

    for (size_t i = 0; i < result.column_names.size(); ++i) {
        const std::string& col_name = result.column_names[i];

        // Skip derived columns (will handle in Phase 2)
        bool is_derived = false;
        for (const auto& proj : analysis.projections) {
            if (proj.name == col_name && !proj.derived_from.empty()) {
                is_derived = true;
                break;
            }
        }
        if (is_derived) continue;

        ColumnClassification classification;
        classification.column_name = col_name;

        // Strategy 1: Column name matching
        auto name_type = classify_by_name(col_name);
        if (name_type.has_value()) {
            classification.type = *name_type;
            classification.confidence = 0.9;
            classification.strategy = "ColumnName";
            base_classifications[col_name] = *name_type;
            classification_result.classifications[col_name] = classification;
            continue;
        }

        // Strategy 2: Type OID hint (if available)
        if (i < result.column_type_oids.size() && result.column_type_oids[i] != 0) {
            auto oid_type = classify_by_type_oid(col_name, result.column_type_oids[i]);
            if (oid_type.has_value()) {
                classification.type = *oid_type;
                classification.confidence = 0.85;
                classification.strategy = "TypeOid";
                base_classifications[col_name] = *oid_type;
                classification_result.classifications[col_name] = classification;
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
            classification.type = *pattern_type;
            classification.confidence = 0.8;
            classification.strategy = "RegexValue";
            base_classifications[col_name] = *pattern_type;
            classification_result.classifications[col_name] = classification;
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

std::optional<ClassificationType> ClassifierRegistry::classify_by_name(const std::string& col_name) {
    std::string lower = utils::to_lower(col_name);

    // Exact match
    auto it = column_patterns_.find(lower);
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
    const std::string& col_name,
    const std::vector<std::string>& sample_values) {

    if (sample_values.empty()) {
        return std::nullopt;
    }

    // Use precompiled regex patterns for performance
    int email_matches = 0;
    int phone_matches = 0;
    int ssn_matches = 0;
    int cc_matches = 0;

    for (const auto& value : sample_values) {
        if (std::regex_search(value, email_regex_)) {
            ++email_matches;
        }
        // Phone: prevent false positives on long digit strings (credit cards, etc.)
        if (std::regex_search(value, phone_regex_)) {
            size_t digit_count = 0;
            for (char c : value) {
                if (std::isdigit(static_cast<unsigned char>(c))) ++digit_count;
            }
            if (digit_count <= 11) {  // Phone numbers are max 11 digits (1 + area + number)
                ++phone_matches;
            }
        }
        // SSN: regex match + structural validation (no 000/666/9xx area)
        if (std::regex_search(value, ssn_regex_) && validate_ssn(value)) {
            ++ssn_matches;
        }
        // Credit card: regex match + Luhn algorithm validation
        if (std::regex_search(value, credit_card_regex_) && luhn_validate(value)) {
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
    std::vector<ClassificationType> source_types;
    for (const auto& source_col : projection.derived_from) {
        auto it = base_classifications.find(source_col);
        if (it != base_classifications.end() && it->second != ClassificationType::NONE) {
            source_types.push_back(it->second);
        }
    }

    if (source_types.empty()) {
        // No PII sources
        return std::nullopt;
    }

    // Use the most sensitive PII type found (higher enum value = more sensitive)
    ClassificationType pii_type = *std::max_element(source_types.begin(), source_types.end());

    // Analyze expression to determine if PII is preserved or destroyed
    std::string expr = utils::to_lower(projection.expression);

    // PII-destroying functions (aggregation, hashing, length)
    const std::vector<std::string> destroyers = {
        "length(", "char_length(", "octet_length(",
        "md5(", "sha", "crypt(",
        "count(", "sum(", "avg(", "min(", "max(",
        "extract(", "date_part("
    };

    for (const auto& func : destroyers) {
        if (expr.find(func) != std::string::npos) {
            // PII destroyed by aggregation/hashing
            return std::nullopt;
        }
    }

    // PII-preserving functions (formatting, string operations)
    // These preserve PII: UPPER, LOWER, TRIM, SUBSTRING, CONCAT, etc.

    // Return classification with slightly lower confidence
    ColumnClassification result;
    result.column_name = projection.name;
    result.type = pii_type;
    result.confidence = 0.9;  // High confidence - derived but still PII
    result.strategy = "DerivedColumn";

    return result;
}

} // namespace sqlproxy
