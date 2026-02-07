#include "db/generic_connection_pool.hpp"
#include "core/utils.hpp"

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
            idle_connections_.push_back(std::move(conn));
        } else {
            utils::log::warn("Failed to create connection " + std::to_string(i+1)
                + " during pool initialization for database '" + db_name_ + "'");
        }
    }

    utils::log::info("ConnectionPool initialized for database '" + db_name_ + "': "
        + std::to_string(total_connections_.load()) + " connections (min="
        + std::to_string(config_.min_connections) + ", max="
        + std::to_string(config_.max_connections) + ")");
}

GenericConnectionPool::~GenericConnectionPool() {
    drain();
}

std::unique_ptr<PooledConnection> GenericConnectionPool::acquire(
    std::chrono::milliseconds timeout) {

    if (shutdown_.load(std::memory_order_acquire)) {
        return nullptr;
    }

    // Check circuit breaker
    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        failed_acquires_.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }

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
    }

    // Validate connection health
    if (!conn->is_healthy(config_.health_check_query)) {
        health_check_failures_.fetch_add(1, std::memory_order_relaxed);
        conn->close();
        total_connections_.fetch_sub(1, std::memory_order_relaxed);

        conn = create_connection();
        if (!conn) {
            semaphore_.release();
            failed_acquires_.fetch_add(1, std::memory_order_relaxed);
            return nullptr;
        }
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

    utils::log::info("ConnectionPool drained for database '" + db_name_ + "'");
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
        conn->close();
        total_connections_.fetch_sub(1, std::memory_order_relaxed);
        semaphore_.release();
        return;
    }

    // Return to idle pool
    {
        std::lock_guard<std::mutex> lock(mutex_);
        idle_connections_.push_back(std::move(conn));
    }

    semaphore_.release();
}

} // namespace sqlproxy
