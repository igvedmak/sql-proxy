#include "executor/connection_pool.hpp"
#include "core/error.hpp"
#include "core/utils.hpp"
#include <format>
#include <thread>

namespace sqlproxy {

// ============================================================================
// PgPooledConnection Implementation
// ============================================================================

PgPooledConnection::PgPooledConnection(PGconn* conn, std::function<void(PGconn*)> return_fn)
    : conn_(conn), return_fn_(std::move(return_fn)) {}

PgPooledConnection::~PgPooledConnection() {
    if (conn_ && return_fn_) {
        return_fn_(conn_);
    }
}

PgPooledConnection::PgPooledConnection(PgPooledConnection&& other) noexcept
    : conn_(other.conn_), return_fn_(std::move(other.return_fn_)) {
    other.conn_ = nullptr;
}

PgPooledConnection& PgPooledConnection::operator=(PgPooledConnection&& other) noexcept {
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
            utils::log::warn(std::format("Failed to create connection {} during pool initialization for database '{}'", i + 1, db_name_));
        }
    }

    // Start background health checker thread
    health_thread_ = std::jthread([this](std::stop_token) { health_check_loop(); });

    utils::log::info(std::format("ConnectionPool initialized for database '{}': {} connections (min={}, max={})",
        db_name_, total_connections_.load(), config_.min_connections, config_.max_connections));
}

ConnectionPool::~ConnectionPool() {
    drain();
}

std::unique_ptr<PgPooledConnection> ConnectionPool::acquire(std::chrono::milliseconds timeout) {
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

    // Fast status check only (no network round-trip).
    // Full health checks run in the background thread.
    if (PQstatus(conn) != CONNECTION_OK) {
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

    return std::make_unique<PgPooledConnection>(conn, return_fn);
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

    // Wake up and join the background health checker
    shutdown_cv_.notify_one();
    if (health_thread_.joinable()) {
        health_thread_.request_stop();
        health_thread_.join();
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // Close all idle connections
    for (PGconn* conn : idle_connections_) {
        if (conn) {
            PQfinish(conn);
            total_connections_.fetch_sub(1, std::memory_order_relaxed);
        }
    }

    idle_connections_.clear();

    utils::log::info(std::format("ConnectionPool drained for database '{}'", db_name_));
}

PGconn* ConnectionPool::create_connection() {
    // Create new PostgreSQL connection
    PGconn* conn = PQconnectdb(config_.connection_string.c_str());

    if (!conn) {
        utils::log::error(std::format("Failed to allocate PGconn for database '{}'", db_name_));
        return nullptr;
    }

    // Check connection status
    if (PQstatus(conn) != CONNECTION_OK) {
        utils::log::error(std::format("Failed to connect to database '{}': {}", db_name_, PQerrorMessage(conn)));
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

    // If shutdown or connection obviously broken, close it immediately
    if (shutdown_.load(std::memory_order_acquire) || PQstatus(conn) != CONNECTION_OK) {
        PQfinish(conn);
        total_connections_.fetch_sub(1, std::memory_order_relaxed);
        semaphore_.release();
        return;
    }

    // Return to idle pool (background thread will health-check it later)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        idle_connections_.push_back(conn);
    }

    // Release semaphore slot
    semaphore_.release();
}

// ============================================================================
// Background Health Checker
// ============================================================================

void ConnectionPool::health_check_loop() {
    constexpr auto kCheckInterval = std::chrono::seconds(10);

    while (!shutdown_.load(std::memory_order_acquire)) {
        // Wait for shutdown signal or timeout
        {
            std::unique_lock<std::mutex> lock(shutdown_mutex_);
            shutdown_cv_.wait_for(lock, kCheckInterval, [this] {
                return shutdown_.load(std::memory_order_acquire);
            });
        }

        if (shutdown_.load(std::memory_order_acquire)) {
            return;
        }

        // Collect idle connections to check (under lock, fast)
        std::deque<PGconn*> to_check;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::swap(to_check, idle_connections_);
        }

        // Health-check outside the lock (slow I/O)
        std::deque<PGconn*> healthy;
        for (PGconn* conn : to_check) {
            if (shutdown_.load(std::memory_order_acquire)) {
                // Shutting down — put remaining back and exit
                healthy.insert(healthy.end(), &conn, &conn + 1);
                // Actually, just push what we haven't checked
                break;
            }

            if (is_connection_healthy(conn)) {
                healthy.push_back(conn);
            } else {
                health_check_failures_.fetch_add(1, std::memory_order_relaxed);
                PQfinish(conn);
                total_connections_.fetch_sub(1, std::memory_order_relaxed);
            }
        }

        // Return healthy connections to idle pool
        if (!healthy.empty()) {
            std::lock_guard<std::mutex> lock(mutex_);
            // Prepend healthy connections (they were checked more recently)
            for (auto it = healthy.rbegin(); it != healthy.rend(); ++it) {
                idle_connections_.push_front(*it);
            }
        }
    }
}

} // namespace sqlproxy
