#pragma once

#include "db/iquery_executor.hpp"

#include <atomic>
#include <memory>
#include <shared_mutex>
#include <vector>

namespace sqlproxy {

/**
 * @brief Routes queries to primary or read replicas based on statement type
 *
 * SELECTs → round-robin across read replicas (falls back to primary if none)
 * Writes (INSERT/UPDATE/DELETE/DDL) → primary only
 *
 * Thread-safe: atomic round-robin counter + shared_mutex for replica list.
 */
class ReplicaRoutingExecutor : public IQueryExecutor {
public:
    explicit ReplicaRoutingExecutor(std::shared_ptr<IQueryExecutor> primary);

    /// Add a read replica executor
    void add_replica(std::shared_ptr<IQueryExecutor> replica);

    /// Remove all replicas (e.g., on failover)
    void clear_replicas();

    /// Number of active replicas
    [[nodiscard]] size_t replica_count() const;

    [[nodiscard]] QueryResult execute(
        const std::string& sql, StatementType stmt_type) override;

    struct Stats {
        uint64_t primary_queries;
        uint64_t replica_queries;
    };
    [[nodiscard]] Stats get_stats() const;

private:
    [[nodiscard]] IQueryExecutor* select_replica();

    std::shared_ptr<IQueryExecutor> primary_;
    std::vector<std::shared_ptr<IQueryExecutor>> replicas_;
    mutable std::shared_mutex replicas_mutex_;
    std::atomic<uint64_t> round_robin_{0};
    std::atomic<uint64_t> primary_queries_{0};
    std::atomic<uint64_t> replica_queries_{0};
};

} // namespace sqlproxy
