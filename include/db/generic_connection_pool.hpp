#pragma once

#include "db/iconnection_pool.hpp"
#include "db/iconnection_factory.hpp"
#include "db/pooled_connection.hpp"
#include "executor/circuit_breaker.hpp"
#include <atomic>
#include <chrono>
#include <deque>
#include <memory>
#include <mutex>
#include <semaphore>
#include <string>
#include <unordered_map>

namespace sqlproxy {

/**
 * @brief Database-agnostic connection pool
 *
 * Reuses the proven semaphore + deque + RAII pattern from the original
 * ConnectionPool, but works with any IDbConnection via IConnectionFactory.
 *
 * Design:
 * - Bounded pool: max_connections enforced via counting_semaphore (C++20)
 * - Lazy initialization: connections created on-demand up to max
 * - Health checking: validates connections before returning from pool
 * - Thread-safe: mutex protects deque, semaphore prevents oversubscription
 * - RAII: PooledConnection auto-returns on destruction
 * - Circuit breaker integration: pool respects breaker state
 *
 * Performance: ~50-100ns to acquire from idle pool
 */
class GenericConnectionPool : public IConnectionPool {
public:
    /**
     * @brief Construct pool with connection factory
     * @param db_name Database name (for logging)
     * @param config Pool configuration
     * @param factory Connection factory (creates IDbConnection instances)
     * @param circuit_breaker Optional circuit breaker for fault isolation
     */
    GenericConnectionPool(
        std::string db_name,
        const PoolConfig& config,
        std::shared_ptr<IConnectionFactory> factory,
        std::shared_ptr<CircuitBreaker> circuit_breaker = nullptr);

    ~GenericConnectionPool() override;

    std::unique_ptr<PooledConnection> acquire(
        std::chrono::milliseconds timeout = std::chrono::milliseconds{5000}) override;

    PoolStats get_stats() const override;

    void drain() override;

    const std::string& name() const override { return db_name_; }

private:
    /**
     * @brief Create new connection via factory
     */
    std::unique_ptr<IDbConnection> create_connection();

    /**
     * @brief Return connection to pool (called by PooledConnection destructor)
     */
    void return_connection(std::unique_ptr<IDbConnection> conn);

    std::string db_name_;
    PoolConfig config_;
    std::shared_ptr<IConnectionFactory> factory_;
    std::shared_ptr<CircuitBreaker> circuit_breaker_;

    // Connection storage
    std::deque<std::unique_ptr<IDbConnection>> idle_connections_;
    mutable std::mutex mutex_;

    // Semaphore for bounded pool (C++20)
    std::counting_semaphore<> semaphore_;

    // Statistics (atomic for lock-free reads)
    std::atomic<size_t> total_connections_{0};
    std::atomic<size_t> total_acquires_{0};
    std::atomic<size_t> total_releases_{0};
    std::atomic<size_t> failed_acquires_{0};
    std::atomic<size_t> health_check_failures_{0};

    // Shutdown flag
    std::atomic<bool> shutdown_{false};

    // Connection lifetime tracking
    std::unordered_map<IDbConnection*, std::chrono::steady_clock::time_point> created_at_;
    std::atomic<size_t> connections_recycled_{0};
};

} // namespace sqlproxy
