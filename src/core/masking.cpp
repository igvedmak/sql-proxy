#include "core/masking.hpp"

#include <openssl/sha.h>

#include <algorithm>
#include <format>
#include <future>
#include <thread>

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

    // Collect masking tasks: column index + masking parameters
    struct MaskTask {
        size_t col_idx;
        MaskingAction action;
        int prefix_len;
        int suffix_len;
    };
    std::vector<MaskTask> tasks;

    for (const auto& decision : decisions) {
        if (decision.decision != Decision::ALLOW || decision.masking == MaskingAction::NONE) {
            continue;
        }
        const auto it = col_idx.find(decision.column_name);
        if (it == col_idx.end()) continue;

        tasks.push_back({it->second, decision.masking, decision.prefix_len, decision.suffix_len});
        records.emplace_back(decision.column_name, decision.masking, decision.matched_policy);
    }

    if (tasks.empty()) return records;

    const size_t num_rows = result.rows.size();
    constexpr size_t kParallelThreshold = 1000;
    const unsigned hw_threads = std::thread::hardware_concurrency();

    // Lambda that masks a range of rows [start, end)
    auto mask_range = [&](size_t start, size_t end) {
        for (size_t r = start; r < end; ++r) {
            auto& row = result.rows[r];
            for (const auto& t : tasks) {
                if (t.col_idx < row.size()) {
                    row[t.col_idx] = mask_value(row[t.col_idx], t.action,
                                                 t.prefix_len, t.suffix_len);
                }
            }
        }
    };

    if (num_rows >= kParallelThreshold && hw_threads > 1) {
        // Parallel path: partition rows among worker threads
        const unsigned num_workers = std::min(hw_threads, 4u);
        const size_t chunk = (num_rows + num_workers - 1) / num_workers;

        std::vector<std::future<void>> futures;
        futures.reserve(num_workers);

        for (unsigned w = 0; w < num_workers; ++w) {
            const size_t start = w * chunk;
            const size_t end = std::min(start + chunk, num_rows);
            if (start >= end) break;
            futures.push_back(std::async(std::launch::async, mask_range, start, end));
        }
        for (auto& f : futures) f.get();
    } else {
        // Sequential path
        mask_range(0, num_rows);
    }

    return records;
}

} // namespace sqlproxy
