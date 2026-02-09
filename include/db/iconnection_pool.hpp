#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

namespace sqlproxy {

// Forward declarations
class PooledConnection;

/**
 * @brief Pool configuration (database-agnostic)
 */
struct PoolConfig {
    std::string connection_string;
    size_t min_connections = 2;
    size_t max_connections = 10;
    std::chrono::milliseconds connection_timeout{5000};
    std::chrono::milliseconds idle_timeout{300000};
    std::string health_check_query{"SELECT 1"};
    std::chrono::seconds max_lifetime{3600};  // 0 = disabled
};

/**
 * @brief Pool statistics for monitoring
 */
struct PoolStats {
    size_t total_connections = 0;
    size_t idle_connections = 0;
    size_t active_connections = 0;
    size_t total_acquires = 0;
    size_t total_releases = 0;
    size_t failed_acquires = 0;
    size_t health_check_failures = 0;
    size_t connections_recycled = 0;

    // Acquire time histogram (microseconds)
    // Buckets: ≤100μs, ≤500μs, ≤1ms, ≤5ms, ≤50ms, +Inf
    uint64_t acquire_time_sum_us = 0;
    uint64_t acquire_time_count = 0;
    std::array<uint64_t, 6> acquire_time_buckets = {};
};

/**
 * @brief Abstract connection pool interface
 */
class IConnectionPool {
public:
    virtual ~IConnectionPool() = default;

    /**
     * @brief Acquire connection from pool (blocking with timeout)
     * @param timeout Max wait time for acquisition
     * @return RAII connection handle or nullptr on timeout/error
     */
    [[nodiscard]] virtual std::unique_ptr<PooledConnection> acquire(
        std::chrono::milliseconds timeout = std::chrono::milliseconds{5000}) = 0;

    /**
     * @brief Get pool statistics (thread-safe)
     */
    [[nodiscard]] virtual PoolStats get_stats() const = 0;

    /**
     * @brief Drain pool - close all idle connections
     */
    virtual void drain() = 0;

    /**
     * @brief Get database name this pool serves
     */
    [[nodiscard]] virtual const std::string& name() const = 0;
};

} // namespace sqlproxy
