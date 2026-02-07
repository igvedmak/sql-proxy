#pragma once

#include "core/types.hpp"
#include "db/iquery_executor.hpp"
#include <atomic>
#include <memory>
#include <vector>

namespace sqlproxy {

class CircuitBreaker;

/**
 * @brief Read/write splitting executor
 *
 * Routes SELECT queries to read replicas (round-robin with circuit breaker
 * failover), all other queries to the primary.
 */
class RoutingQueryExecutor : public IQueryExecutor {
public:
    struct ReplicaEntry {
        std::shared_ptr<IQueryExecutor> executor;
        std::shared_ptr<CircuitBreaker> circuit_breaker;
        int weight;
    };

    RoutingQueryExecutor(
        std::shared_ptr<IQueryExecutor> primary,
        std::vector<ReplicaEntry> replicas);

    [[nodiscard]] QueryResult execute(
        const std::string& sql, StatementType stmt_type) override;

    [[nodiscard]] size_t healthy_replica_count() const;

private:
    IQueryExecutor* select_replica();

    std::shared_ptr<IQueryExecutor> primary_;
    std::vector<ReplicaEntry> replicas_;
    std::atomic<uint64_t> round_robin_counter_{0};
};

} // namespace sqlproxy
