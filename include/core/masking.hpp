#pragma once

#include "core/types.hpp"
#include <string>
#include <string_view>
#include <vector>

namespace sqlproxy {

/**
 * @brief Data masking engine - applies masking strategies to query results
 *
 * Strategies:
 * - REDACT:   Replace entire value with "***REDACTED***"
 * - PARTIAL:  Show prefix + "***" + suffix (e.g., "ali***com")
 * - HASH:     SHA256 first 16 hex chars (deterministic pseudonymization)
 * - NULLIFY:  Replace with "NULL"
 */
class MaskingEngine {
public:
    /**
     * @brief Mask a single value
     */
    [[nodiscard]] static std::string mask_value(
        std::string_view value,
        MaskingAction action,
        int prefix_len = 3,
        int suffix_len = 3);

    /**
     * @brief Apply masking to query results based on column decisions
     * @param result Query result (modified in-place)
     * @param decisions Column-level decisions from policy engine
     * @return Records of which columns were masked
     */
    [[nodiscard]] static std::vector<MaskingRecord> apply(
        QueryResult& result,
        const std::vector<ColumnPolicyDecision>& decisions);

private:
    static std::string partial_mask(std::string_view value, int prefix_len, int suffix_len);
    static std::string hash_value(std::string_view value);
};

} // namespace sqlproxy
