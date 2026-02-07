#pragma once

#include "core/types.hpp"
#include "analyzer/sql_analyzer.hpp"
#include <vector>
#include <memory>
#include <unordered_map>
#include <regex>

namespace sqlproxy {

/**
 * @brief Classifier registry - runs strategy chain for PII detection
 *
 * 4-stage classification:
 * 1. Column name matching (fast, 90% confidence)
 * 2. Type OID hints from PostgreSQL (medium, 85% confidence)
 * 3. Regex value matching (slow, 80% confidence)
 * 4. Derived column tracking (inherited PII)
 */
class ClassifierRegistry {
public:
    ClassifierRegistry();

    /**
     * @brief Classify query results
     * @param result Query execution result
     * @param analysis SQL analysis with derived_from tracking
     * @return Classification result
     */
    ClassificationResult classify(
        const QueryResult& result,
        const AnalysisResult& analysis
    ) const;

private:
    /**
     * @brief Classify by column name (Strategy 1)
     */
    std::optional<ClassificationType> classify_by_name(const std::string& col_name) const;

    /**
     * @brief Classify by PostgreSQL type OID (Strategy 2)
     */
    static std::optional<ClassificationType> classify_by_type_oid(
        const std::string& col_name,
        uint32_t type_oid
    );

    /**
     * @brief Classify by data pattern (Strategy 3)
     */
    std::optional<ClassificationType> classify_by_pattern(
        const std::string& col_name,
        const std::vector<std::string>& sample_values
    ) const;

    /**
     * @brief Classify derived columns (Strategy 4)
     */
    static std::optional<ColumnClassification> classify_derived_column(
        const ProjectionColumn& projection,
        const std::unordered_map<std::string, ClassificationType>& base_classifications
    );

    // Classification patterns
    std::unordered_map<std::string, ClassificationType> column_patterns_;

    // Precompiled regex patterns for performance
    std::regex email_regex_;
    std::regex phone_regex_;
    std::regex ssn_regex_;
    std::regex credit_card_regex_;
};

} // namespace sqlproxy
