#pragma once

#include "core/types.hpp"
#include "db/iconnection_pool.hpp"
#include <atomic>
#include <chrono>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace sqlproxy {

/**
 * @brief Query Cost Estimator — runs EXPLAIN before execution to reject expensive queries.
 *
 * Inserts between policy evaluation and query execution (Layer 4.8).
 * Only runs on SELECT statements (DML/DDL skip cost check).
 * Parses PostgreSQL EXPLAIN output for estimated rows and total cost.
 */
class QueryCostEstimator {
public:
    struct Config {
        bool enabled{false};
        double max_cost{100000.0};
        uint64_t max_estimated_rows{1000000};
        bool log_estimates{false};
        std::chrono::seconds cache_ttl{300};  // Cache EXPLAIN results for 5 minutes
    };

    struct CostEstimate {
        double total_cost{0.0};
        uint64_t estimated_rows{0};
        std::string plan_type;
        bool exceeded_cost{false};
        bool exceeded_rows{false};

        [[nodiscard]] bool is_rejected() const { return exceeded_cost || exceeded_rows; }
    };

    explicit QueryCostEstimator(std::shared_ptr<IConnectionPool> pool, Config config);

    /**
     * @brief Estimate query cost using EXPLAIN
     * @param sql The SQL query to estimate
     * @param fingerprint_hash Optional query fingerprint for caching
     * @return Cost estimate with rejection flags
     */
    [[nodiscard]] CostEstimate estimate(const std::string& sql,
                                         uint64_t fingerprint_hash = 0) const;

    [[nodiscard]] bool is_enabled() const { return config_.enabled; }
    [[nodiscard]] uint64_t total_rejected() const { return rejected_.load(std::memory_order_relaxed); }
    [[nodiscard]] uint64_t total_estimated() const { return estimated_.load(std::memory_order_relaxed); }

private:
    std::shared_ptr<IConnectionPool> pool_;
    Config config_;
    mutable std::atomic<uint64_t> rejected_{0};
    mutable std::atomic<uint64_t> estimated_{0};
    mutable std::atomic<uint64_t> cache_hits_{0};

    /**
     * @brief Parse EXPLAIN output for cost and rows
     */
    static CostEstimate parse_explain_output(const std::string& explain_text);

    /**
     * @brief EXPLAIN result cache (fingerprint → cached estimate)
     */
    struct CachedEstimate {
        CostEstimate estimate;
        std::chrono::steady_clock::time_point cached_at;
    };
    mutable std::unordered_map<uint64_t, CachedEstimate> estimate_cache_;
    mutable std::shared_mutex cache_mutex_;
};

} // namespace sqlproxy
