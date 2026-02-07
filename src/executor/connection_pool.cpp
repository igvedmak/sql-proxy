#include "executor/connection_pool.hpp"
#include "core/error.hpp"
#include "core/utils.hpp"
#include <thread>

namespace sqlproxy {

// ============================================================================
// PooledConnection Implementation
// ============================================================================

PooledConnection::PooledConnection(PGconn* conn, std::function<void(PGconn*)> return_fn)
    : conn_(conn), return_fn_(std::move(return_fn)) {}

PooledConnection::~PooledConnection() {
    if (conn_ && return_fn_) {
        return_fn_(conn_);
    }
}

PooledConnection::PooledConnection(PooledConnection&& other) noexcept
    : conn_(other.conn_), return_fn_(std::move(other.return_fn_)) {
    other.conn_ = nullptr;
}

PooledConnection& PooledConnection::operator=(PooledConnection&& other) noexcept {
    if (this != &other) {
        // Return current connection before taking new one
        if (conn_ && return_fn_) {
            return_fn_(conn_);
        }
        conn_ = other.conn_;
        return_fn_ = std::move(other.return_fn_);
        other.conn_ = nullptr;
    }
    return *this;
}

// ============================================================================
// ConnectionPool Implementation
// ============================================================================

ConnectionPool::ConnectionPool(
    std::string db_name,
    const Config& config,
    std::shared_ptr<CircuitBreaker> circuit_breaker)
    : db_name_(std::move(db_name)),
      config_(config),
      circuit_breaker_(std::move(circuit_breaker)),
      semaphore_(config.max_connections) {

    // Pre-warm pool with min_connections
    for (size_t i = 0; i < config_.min_connections; ++i) {
        PGconn* conn = create_connection();
        if (conn) {
            std::lock_guard<std::mutex> lock(mutex_);
            idle_connections_.push_back(conn);
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

ConnectionPool::~ConnectionPool() {
    drain();
}

std::unique_ptr<PooledConnection> ConnectionPool::acquire(std::chrono::milliseconds timeout) {
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
        // Timeout waiting for slot
        failed_acquires_.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }

    total_acquires_.fetch_add(1, std::memory_order_relaxed);

    PGconn* conn = nullptr;

    // Try to get connection from idle pool
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!idle_connections_.empty()) {
            conn = idle_connections_.front();
            idle_connections_.pop_front();
        }
    }

    // If no idle connection, create a new one
    if (!conn) {
        conn = create_connection();
        if (!conn) {
            // Failed to create connection - release semaphore
            semaphore_.release();
            failed_acquires_.fetch_add(1, std::memory_order_relaxed);
            return nullptr;
        }
    }

    // Validate connection health
    if (!is_connection_healthy(conn)) {
        // Connection unhealthy - close it and create new one
        health_check_failures_.fetch_add(1, std::memory_order_relaxed);
        PQfinish(conn);
        total_connections_.fetch_sub(1, std::memory_order_relaxed);

        conn = create_connection();
        if (!conn) {
            semaphore_.release();
            failed_acquires_.fetch_add(1, std::memory_order_relaxed);
            return nullptr;
        }
    }

    // Create RAII handle with return callback
    auto return_fn = [this](PGconn* c) {
        this->return_connection(c);
    };

    return std::make_unique<PooledConnection>(conn, return_fn);
}

ConnectionPool::Stats ConnectionPool::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);

    Stats stats;
    stats.total_connections = total_connections_.load(std::memory_order_relaxed);
    stats.idle_connections = idle_connections_.size();
    stats.active_connections = stats.total_connections - stats.idle_connections;
    stats.total_acquires = total_acquires_.load(std::memory_order_relaxed);
    stats.total_releases = total_releases_.load(std::memory_order_relaxed);
    stats.failed_acquires = failed_acquires_.load(std::memory_order_relaxed);
    stats.health_check_failures = health_check_failures_.load(std::memory_order_relaxed);

    return stats;
}

void ConnectionPool::drain() {
    shutdown_.store(true, std::memory_order_release);

    std::lock_guard<std::mutex> lock(mutex_);

    // Close all idle connections
    for (PGconn* conn : idle_connections_) {
        if (conn) {
            PQfinish(conn);
            total_connections_.fetch_sub(1, std::memory_order_relaxed);
        }
    }

    idle_connections_.clear();

    utils::log::info("ConnectionPool drained for database '" + db_name_ + "'");
}

PGconn* ConnectionPool::create_connection() {
    // Create new PostgreSQL connection
    PGconn* conn = PQconnectdb(config_.connection_string.c_str());

    if (!conn) {
        utils::log::error("Failed to allocate PGconn for database '" + db_name_ + "'");
        return nullptr;
    }

    // Check connection status
    if (PQstatus(conn) != CONNECTION_OK) {
        utils::log::error("Failed to connect to database '" + db_name_ + "': "
            + std::string(PQerrorMessage(conn)));
        PQfinish(conn);
        return nullptr;
    }

    total_connections_.fetch_add(1, std::memory_order_relaxed);

    return conn;
}

bool ConnectionPool::is_connection_healthy(PGconn* conn) {
    if (!conn) {
        return false;
    }

    // Check basic connection status
    if (PQstatus(conn) != CONNECTION_OK) {
        return false;
    }

    // Execute health check query
    PGresult* res = PQexec(conn, config_.health_check_query.c_str());
    if (!res) {
        return false;
    }

    ExecStatusType status = PQresultStatus(res);
    PQclear(res);

    return (status == PGRES_TUPLES_OK || status == PGRES_COMMAND_OK);
}

void ConnectionPool::return_connection(PGconn* conn) {
    if (!conn) {
        return;
    }

    total_releases_.fetch_add(1, std::memory_order_relaxed);

    // If shutdown or connection unhealthy, close it
    if (shutdown_.load(std::memory_order_acquire) || !is_connection_healthy(conn)) {
        PQfinish(conn);
        total_connections_.fetch_sub(1, std::memory_order_relaxed);
        semaphore_.release();
        return;
    }

    // Return to idle pool
    {
        std::lock_guard<std::mutex> lock(mutex_);
        idle_connections_.push_back(conn);
    }

    // Release semaphore slot
    semaphore_.release();
}

} // namespace sqlproxy
