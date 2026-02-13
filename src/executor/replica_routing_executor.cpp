#include "executor/replica_routing_executor.hpp"

namespace sqlproxy {

ReplicaRoutingExecutor::ReplicaRoutingExecutor(std::shared_ptr<IQueryExecutor> primary)
    : primary_(std::move(primary)) {}

void ReplicaRoutingExecutor::add_replica(std::shared_ptr<IQueryExecutor> replica) {
    std::unique_lock lock(replicas_mutex_);
    replicas_.push_back(std::move(replica));
}

void ReplicaRoutingExecutor::clear_replicas() {
    std::unique_lock lock(replicas_mutex_);
    replicas_.clear();
}

size_t ReplicaRoutingExecutor::replica_count() const {
    std::shared_lock lock(replicas_mutex_);
    return replicas_.size();
}

IQueryExecutor* ReplicaRoutingExecutor::select_replica() {
    std::shared_lock lock(replicas_mutex_);
    if (replicas_.empty()) return nullptr;
    const auto idx = round_robin_.fetch_add(1, std::memory_order_relaxed) % replicas_.size();
    return replicas_[idx].get();
}

QueryResult ReplicaRoutingExecutor::execute(
    const std::string& sql, StatementType stmt_type) {

    // Route SELECTs to replicas, everything else to primary
    if (stmt_type == StatementType::SELECT) {
        auto* replica = select_replica();
        if (replica) {
            replica_queries_.fetch_add(1, std::memory_order_relaxed);
            return replica->execute(sql, stmt_type);
        }
        // No replicas available — fall through to primary
    }

    primary_queries_.fetch_add(1, std::memory_order_relaxed);
    return primary_->execute(sql, stmt_type);
}

ReplicaRoutingExecutor::Stats ReplicaRoutingExecutor::get_stats() const {
    return {
        .primary_queries = primary_queries_.load(std::memory_order_relaxed),
        .replica_queries = replica_queries_.load(std::memory_order_relaxed),
    };
}

} // namespace sqlproxy
