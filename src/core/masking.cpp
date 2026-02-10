#include "core/masking.hpp"

#include <openssl/sha.h>

#include <algorithm>
#include <format>

namespace sqlproxy {

static constexpr std::string_view kRedacted = "***REDACTED***";
static constexpr std::string_view kMaskFill = "***";

std::string MaskingEngine::mask_value(
    std::string_view value,
    MaskingAction action,
    int prefix_len,
    int suffix_len) {

    switch (action) {
        case MaskingAction::NONE:
            return std::string(value);

        case MaskingAction::REDACT:
            return std::string(kRedacted);

        case MaskingAction::PARTIAL:
            return partial_mask(value, prefix_len, suffix_len);

        case MaskingAction::HASH:
            return hash_value(value);

        case MaskingAction::NULLIFY:
            return "NULL";
    }
    return std::string(kRedacted);
}

std::string MaskingEngine::partial_mask(
    std::string_view value, int prefix_len, int suffix_len) {

    const auto len = static_cast<int>(value.size());

    // If value too short for partial masking, redact entirely
    if (len <= prefix_len + suffix_len) {
        return std::string(kRedacted);
    }

    std::string result;
    result.reserve(prefix_len + kMaskFill.size() + suffix_len);
    result.append(value.data(), prefix_len);
    result.append(kMaskFill);
    result.append(value.data() + len - suffix_len, suffix_len);
    return result;
}

std::string MaskingEngine::hash_value(std::string_view value) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(value.data()),
           value.size(), hash);

    // First 16 hex chars (8 bytes)
    std::string result;
    result.reserve(16);
    for (int i = 0; i < 8; ++i) {
        result += std::format("{:02x}", hash[i]);
    }
    return result;
}

std::vector<MaskingRecord> MaskingEngine::apply(
    QueryResult& result,
    const std::vector<ColumnPolicyDecision>& decisions) {

    std::vector<MaskingRecord> records;

    if (result.column_names.empty() || decisions.empty()) {
        return records;
    }

    // Build column index: name → position
    std::unordered_map<std::string, size_t> col_idx;
    col_idx.reserve(result.column_names.size());
    for (size_t i = 0; i < result.column_names.size(); ++i) {
        col_idx[result.column_names[i]] = i;
    }

    // Apply masking for each decision that has a non-NONE masking action
    for (const auto& decision : decisions) {
        if (decision.decision != Decision::ALLOW || decision.masking == MaskingAction::NONE) {
            continue;
        }

        const auto it = col_idx.find(decision.column_name);
        if (it == col_idx.end()) continue;
        const size_t idx = it->second;

        // Mask all rows in this column
        for (auto& row : result.rows) {
            if (idx < row.size()) {
                row[idx] = mask_value(row[idx], decision.masking,
                                       decision.prefix_len, decision.suffix_len);
            }
        }

        records.emplace_back(decision.column_name, decision.masking, decision.matched_policy);
    }

    return records;
}

} // namespace sqlproxy
