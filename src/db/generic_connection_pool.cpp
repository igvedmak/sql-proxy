#include "db/generic_connection_pool.hpp"
#include "core/utils.hpp"
#include <format>

namespace sqlproxy {

GenericConnectionPool::GenericConnectionPool(
    std::string db_name,
    const PoolConfig& config,
    std::shared_ptr<IConnectionFactory> factory,
    std::shared_ptr<CircuitBreaker> circuit_breaker)
    : db_name_(std::move(db_name)),
      config_(config),
      factory_(std::move(factory)),
      circuit_breaker_(std::move(circuit_breaker)),
      semaphore_(config.max_connections) {

    // Pre-warm pool with min_connections
    for (size_t i = 0; i < config_.min_connections; ++i) {
        auto conn = create_connection();
        if (conn) {
            std::lock_guard<std::mutex> lock(mutex_);
            created_at_[conn.get()] = std::chrono::steady_clock::now();
            idle_connections_.emplace_back(std::move(conn));
        } else {
            utils::log::warn(std::format("Failed to create connection {} during pool initialization for database '{}'", i + 1, db_name_));
        }
    }

    utils::log::info(std::format("ConnectionPool initialized for database '{}': {} connections (min={}, max={})",
        db_name_, total_connections_.load(), config_.min_connections, config_.max_connections));
}

GenericConnectionPool::~GenericConnectionPool() {
    drain();
}

std::unique_ptr<PooledConnection> GenericConnectionPool::acquire(
    std::chrono::milliseconds timeout) {

    const auto acquire_start = std::chrono::steady_clock::now();

    if (shutdown_.load(std::memory_order_acquire)) {
        return nullptr;
    }

    // Note: Circuit breaker is checked by QueryExecutor before calling acquire().
    // Checking it here would double-count half_open_calls, preventing recovery.

    // Acquire semaphore slot (blocks if pool full)
    if (!semaphore_.try_acquire_for(timeout)) {
        failed_acquires_.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }

    total_acquires_.fetch_add(1, std::memory_order_relaxed);

    std::unique_ptr<IDbConnection> conn;

    // Try to get connection from idle pool
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!idle_connections_.empty()) {
            conn = std::move(idle_connections_.front());
            idle_connections_.pop_front();
        }
    }

    // If no idle connection, create a new one
    if (!conn) {
        conn = create_connection();
        if (!conn) {
            semaphore_.release();
            failed_acquires_.fetch_add(1, std::memory_order_relaxed);
            return nullptr;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        created_at_[conn.get()] = std::chrono::steady_clock::now();
    }

    // Check max_lifetime: recycle if connection is too old
    if (config_.max_lifetime.count() > 0) {
        std::chrono::steady_clock::time_point birth;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const auto it = created_at_.find(conn.get());
            if (it != created_at_.end()) birth = it->second;
        }
        const auto age = std::chrono::steady_clock::now() - birth;
        if (age > config_.max_lifetime) {
            // Recycle: close old, create new
            {
                std::lock_guard<std::mutex> lock(mutex_);
                created_at_.erase(conn.get());
            }
            conn->close();
            total_connections_.fetch_sub(1, std::memory_order_relaxed);
            connections_recycled_.fetch_add(1, std::memory_order_relaxed);

            conn = create_connection();
            if (!conn) {
                semaphore_.release();
                failed_acquires_.fetch_add(1, std::memory_order_relaxed);
                return nullptr;
            }
            std::lock_guard<std::mutex> lock(mutex_);
            created_at_[conn.get()] = std::chrono::steady_clock::now();
        }
    }

    // Validate connection health
    if (!conn->is_healthy(config_.health_check_query)) {
        health_check_failures_.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            created_at_.erase(conn.get());
        }
        conn->close();
        total_connections_.fetch_sub(1, std::memory_order_relaxed);

        conn = create_connection();
        if (!conn) {
            semaphore_.release();
            failed_acquires_.fetch_add(1, std::memory_order_relaxed);
            return nullptr;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        created_at_[conn.get()] = std::chrono::steady_clock::now();
    }

    // Record acquire time histogram
    {
        const auto elapsed = std::chrono::steady_clock::now() - acquire_start;
        const auto us = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count());
        acquire_time_sum_us_.fetch_add(us, std::memory_order_relaxed);
        acquire_time_count_.fetch_add(1, std::memory_order_relaxed);

        // Buckets: ≤100μs, ≤500μs, ≤1ms, ≤5ms, ≤50ms, +Inf
        size_t bucket = 5;  // +Inf
        if (us <= 100)       bucket = 0;
        else if (us <= 500)  bucket = 1;
        else if (us <= 1000) bucket = 2;
        else if (us <= 5000) bucket = 3;
        else if (us <= 50000) bucket = 4;
        acquire_time_buckets_[bucket].fetch_add(1, std::memory_order_relaxed);
    }

    // Create RAII handle with return callback
    auto return_fn = [this](std::unique_ptr<IDbConnection> c) {
        this->return_connection(std::move(c));
    };

    return std::make_unique<PooledConnection>(std::move(conn), return_fn);
}

PoolStats GenericConnectionPool::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);

    PoolStats stats;
    stats.total_connections = total_connections_.load(std::memory_order_relaxed);
    stats.idle_connections = idle_connections_.size();
    stats.active_connections = stats.total_connections - stats.idle_connections;
    stats.total_acquires = total_acquires_.load(std::memory_order_relaxed);
    stats.total_releases = total_releases_.load(std::memory_order_relaxed);
    stats.failed_acquires = failed_acquires_.load(std::memory_order_relaxed);
    stats.health_check_failures = health_check_failures_.load(std::memory_order_relaxed);
    stats.connections_recycled = connections_recycled_.load(std::memory_order_relaxed);

    stats.acquire_time_sum_us = acquire_time_sum_us_.load(std::memory_order_relaxed);
    stats.acquire_time_count = acquire_time_count_.load(std::memory_order_relaxed);
    for (size_t i = 0; i < acquire_time_buckets_.size(); ++i) {
        stats.acquire_time_buckets[i] = acquire_time_buckets_[i].load(std::memory_order_relaxed);
    }

    return stats;
}

void GenericConnectionPool::drain() {
    shutdown_.store(true, std::memory_order_release);

    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& conn : idle_connections_) {
        if (conn) {
            conn->close();
            total_connections_.fetch_sub(1, std::memory_order_relaxed);
        }
    }

    idle_connections_.clear();
    created_at_.clear();

    utils::log::info(std::format("ConnectionPool drained for database '{}'", db_name_));
}

std::unique_ptr<IDbConnection> GenericConnectionPool::create_connection() {
    auto conn = factory_->create(config_.connection_string);
    if (conn) {
        total_connections_.fetch_add(1, std::memory_order_relaxed);
    }
    return conn;
}

void GenericConnectionPool::return_connection(std::unique_ptr<IDbConnection> conn) {
    if (!conn) {
        return;
    }

    total_releases_.fetch_add(1, std::memory_order_relaxed);

    // If shutdown or connection unhealthy, close it
    if (shutdown_.load(std::memory_order_acquire) ||
        !conn->is_healthy(config_.health_check_query)) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            created_at_.erase(conn.get());
        }
        conn->close();
        total_connections_.fetch_sub(1, std::memory_order_relaxed);
        semaphore_.release();
        return;
    }

    // Return to idle pool
    {
        std::lock_guard<std::mutex> lock(mutex_);
        idle_connections_.emplace_back(std::move(conn));
    }

    semaphore_.release();
}

} // namespace sqlproxy
