#include "core/query_cost_estimator.hpp"
#include "core/utils.hpp"
#include "db/pooled_connection.hpp"
#include <charconv>
#include <format>
#include <string_view>

namespace sqlproxy {

QueryCostEstimator::QueryCostEstimator(
    std::shared_ptr<IConnectionPool> pool, Config config)
    : pool_(std::move(pool)), config_(std::move(config)) {}

QueryCostEstimator::CostEstimate QueryCostEstimator::estimate(
    const std::string& sql, uint64_t fingerprint_hash) const {
    CostEstimate result;

    if (!config_.enabled || !pool_) return result;

    estimated_.fetch_add(1, std::memory_order_relaxed);

    // Fast path: check cache by fingerprint (shared lock)
    if (fingerprint_hash != 0) {
        std::shared_lock lock(cache_mutex_);
        const auto it = estimate_cache_.find(fingerprint_hash);
        if (it != estimate_cache_.end()) {
            const auto age = std::chrono::steady_clock::now() - it->second.cached_at;
            if (age < config_.cache_ttl) {
                cache_hits_.fetch_add(1, std::memory_order_relaxed);
                return it->second.estimate;
            }
        }
    }

    // Slow path: run EXPLAIN (not EXPLAIN ANALYZE — we don't execute the query)
    const std::string explain_sql = "EXPLAIN " + sql;

    const auto conn_handle = pool_->acquire(std::chrono::milliseconds{3000});
    if (!conn_handle || !conn_handle->is_valid()) return result;

    const auto db_result = conn_handle->get()->execute(explain_sql);
    if (!db_result.success || db_result.rows.empty()) {
        return result;  // EXPLAIN failed — don't block, let execution handle errors
    }

    // Collect all EXPLAIN output lines
    std::string explain_text;
    for (const auto& row : db_result.rows) {
        if (!row.empty()) {
            explain_text += row[0];
            explain_text += '\n';
        }
    }

    // Parse the EXPLAIN output
    result = parse_explain_output(explain_text);

    // Check thresholds
    if (result.total_cost > config_.max_cost) {
        result.exceeded_cost = true;
    }
    if (result.estimated_rows > config_.max_estimated_rows) {
        result.exceeded_rows = true;
    }

    if (result.is_rejected()) {
        rejected_.fetch_add(1, std::memory_order_relaxed);
    }

    if (config_.log_estimates) {
        utils::log::info(std::format("EXPLAIN: cost={:.2f} rows={} plan={} rejected={}",
            result.total_cost, result.estimated_rows, result.plan_type,
            result.is_rejected() ? "yes" : "no"));
    }

    // Cache the result by fingerprint
    if (fingerprint_hash != 0) {
        std::unique_lock lock(cache_mutex_);
        estimate_cache_[fingerprint_hash] = {result, std::chrono::steady_clock::now()};
    }

    return result;
}

QueryCostEstimator::CostEstimate QueryCostEstimator::parse_explain_output(
    const std::string& explain_text) {
    CostEstimate result;

    // PostgreSQL EXPLAIN output format (first line):
    // "Seq Scan on customers  (cost=0.00..35.50 rows=2550 width=36)"
    // "Index Scan using pk on customers  (cost=0.15..8.17 rows=1 width=36)"

    std::string_view text = explain_text;

    // Extract plan type (everything before the first '(')
    const auto paren_pos = text.find('(');
    if (paren_pos != std::string_view::npos) {
        auto plan_sv = text.substr(0, paren_pos);
        // Trim trailing spaces
        while (!plan_sv.empty() && plan_sv.back() == ' ') {
            plan_sv.remove_suffix(1);
        }
        // Extract just the scan type (before "on" keyword)
        const auto on_pos = plan_sv.find(" on ");
        if (on_pos != std::string_view::npos) {
            result.plan_type = std::string(plan_sv.substr(0, on_pos));
        } else {
            result.plan_type = std::string(plan_sv);
        }
        // Trim leading spaces/arrows
        while (!result.plan_type.empty() &&
               (result.plan_type[0] == ' ' || result.plan_type[0] == '-' || result.plan_type[0] == '>')) {
            result.plan_type.erase(0, 1);
        }
    }

    // Extract cost: "cost=X..Y" — we want Y (total cost)
    const auto cost_pos = text.find("cost=");
    if (cost_pos != std::string_view::npos) {
        const auto dots = text.find("..", cost_pos + 5);
        if (dots != std::string_view::npos) {
            const auto space = text.find_first_of(" )", dots + 2);
            if (space != std::string_view::npos) {
                auto cost_str = text.substr(dots + 2, space - dots - 2);
                std::from_chars(cost_str.data(), cost_str.data() + cost_str.size(), result.total_cost);
            }
        }
    }

    // Extract rows: "rows=N"
    const auto rows_pos = text.find("rows=");
    if (rows_pos != std::string_view::npos) {
        const auto space = text.find_first_of(" )", rows_pos + 5);
        if (space != std::string_view::npos) {
            auto rows_str = text.substr(rows_pos + 5, space - rows_pos - 5);
            std::from_chars(rows_str.data(), rows_str.data() + rows_str.size(), result.estimated_rows);
        }
    }

    return result;
}

} // namespace sqlproxy
