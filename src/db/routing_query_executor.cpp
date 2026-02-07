#include "db/routing_query_executor.hpp"
#include "executor/circuit_breaker.hpp"

namespace sqlproxy {

RoutingQueryExecutor::RoutingQueryExecutor(
    std::shared_ptr<IQueryExecutor> primary,
    std::vector<ReplicaEntry> replicas)
    : primary_(std::move(primary)),
      replicas_(std::move(replicas)) {}

QueryResult RoutingQueryExecutor::execute(
    const std::string& sql, StatementType stmt_type) {

    // Non-SELECT → always primary
    if (stmt_type != StatementType::SELECT) {
        return primary_->execute(sql, stmt_type);
    }

    // SELECT → try replica, fallback to primary
    IQueryExecutor* replica = select_replica();
    if (!replica) {
        return primary_->execute(sql, stmt_type);
    }

    auto result = replica->execute(sql, stmt_type);

    // On replica failure, try primary as fallback
    if (!result.success) {
        return primary_->execute(sql, stmt_type);
    }

    return result;
}

IQueryExecutor* RoutingQueryExecutor::select_replica() {
    if (replicas_.empty()) return nullptr;

    const size_t n = replicas_.size();
    const uint64_t start = round_robin_counter_.fetch_add(1, std::memory_order_relaxed);

    // Try each replica starting from round-robin position
    for (size_t i = 0; i < n; ++i) {
        size_t idx = (start + i) % n;
        auto& entry = replicas_[idx];

        // Skip replicas with OPEN circuit breaker
        if (entry.circuit_breaker && !entry.circuit_breaker->allow_request()) {
            continue;
        }

        return entry.executor.get();
    }

    // All replicas down
    return nullptr;
}

size_t RoutingQueryExecutor::healthy_replica_count() const {
    size_t count = 0;
    for (const auto& entry : replicas_) {
        if (!entry.circuit_breaker || entry.circuit_breaker->allow_request()) {
            ++count;
        }
    }
    return count;
}

} // namespace sqlproxy
