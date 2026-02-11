#include "analyzer/index_recommender.hpp"
#include "analyzer/sql_analyzer.hpp"

#include <algorithm>
#include <format>
#include <mutex>

namespace sqlproxy {

IndexRecommender::IndexRecommender() : IndexRecommender(Config{}) {}

IndexRecommender::IndexRecommender(Config config)
    : config_(std::move(config)) {}

void IndexRecommender::record(const AnalysisResult& analysis, uint64_t /*fingerprint*/,
                              std::chrono::microseconds exec_time) {
    if (!config_.enabled) return;
    if (analysis.filter_columns.empty() || analysis.source_tables.empty()) return;

    // Build sorted column list for consistent key generation
    std::vector<std::string> cols;
    cols.reserve(analysis.filter_columns.size());
    for (const auto& fc : analysis.filter_columns) {
        cols.push_back(fc.column);
    }
    std::sort(cols.begin(), cols.end());

    // For each source table, record the filter pattern
    for (const auto& table_ref : analysis.source_tables) {
        const auto& table = table_ref.table;
        if (table.empty()) continue;

        // Build key: "table:col1,col2"
        std::string key;
        key.reserve(table.size() + 1 + cols.size() * 16);
        key = table;
        key += ':';
        for (size_t i = 0; i < cols.size(); ++i) {
            if (i > 0) key += ',';
            key += cols[i];
        }

        const double time_us = static_cast<double>(exec_time.count());

        // Fast path: shared lock to check if pattern exists
        {
            std::shared_lock lock(mutex_);
            auto it = patterns_.find(key);
            if (it != patterns_.end()) {
                // Pattern exists - but we need a unique lock to update
                // Fall through to unique lock path
            }
        }

        // Slow path: unique lock to insert/update
        std::unique_lock lock(mutex_);
        auto [it, inserted] = patterns_.try_emplace(key, FilterPattern{});
        if (inserted) {
            it->second.table = table;
            it->second.columns = cols;
        }
        it->second.count++;
        it->second.total_time_us += time_us;
    }
}

std::vector<IndexRecommender::Recommendation> IndexRecommender::get_recommendations() const {
    std::shared_lock lock(mutex_);

    std::vector<Recommendation> results;
    results.reserve(patterns_.size());

    for (const auto& [key, pattern] : patterns_) {
        if (pattern.count < config_.min_occurrences) continue;

        Recommendation rec;
        rec.table = pattern.table;
        rec.columns = pattern.columns;
        rec.occurrence_count = pattern.count;
        rec.avg_execution_time_us = pattern.total_time_us / pattern.count;

        // Build reason
        rec.reason = std::format("Filtered {} times with avg {:.0f}us execution time",
                                 pattern.count, rec.avg_execution_time_us);

        // Build suggested DDL: CREATE INDEX idx_tablename_col1_col2 ON tablename(col1, col2)
        std::string idx_name = "idx_" + pattern.table;
        std::string col_list;
        for (size_t i = 0; i < pattern.columns.size(); ++i) {
            idx_name += '_';
            idx_name += pattern.columns[i];
            if (i > 0) col_list += ", ";
            col_list += pattern.columns[i];
        }

        rec.suggested_ddl = std::format("CREATE INDEX {} ON {}({})",
                                        idx_name, pattern.table, col_list);

        results.push_back(std::move(rec));
    }

    // Sort by occurrence_count descending
    std::sort(results.begin(), results.end(),
              [](const Recommendation& a, const Recommendation& b) {
                  return a.occurrence_count > b.occurrence_count;
              });

    // Limit to max_recommendations
    if (results.size() > config_.max_recommendations) {
        results.resize(config_.max_recommendations);
    }

    return results;
}

} // namespace sqlproxy
