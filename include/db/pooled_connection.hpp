#pragma once

#include "db/idb_connection.hpp"
#include <functional>
#include <memory>

namespace sqlproxy {

/**
 * @brief RAII wrapper for database connection
 *
 * Automatically returns connection to pool on destruction.
 * Move-only to prevent accidental copying.
 * Wraps IDbConnection instead of raw PGconn*.
 */
class PooledConnection {
public:
    using ReturnFunc = std::function<void(std::unique_ptr<IDbConnection>)>;

    /**
     * @brief Construct pooled connection with return callback
     * @param conn Database connection
     * @param return_fn Function to call on destruction (returns to pool)
     */
    PooledConnection(std::unique_ptr<IDbConnection> conn, ReturnFunc return_fn);

    /**
     * @brief Destructor - automatically returns connection to pool
     */
    ~PooledConnection();

    // Move constructor
    PooledConnection(PooledConnection&& other) noexcept;

    // Move assignment
    PooledConnection& operator=(PooledConnection&& other) noexcept;

    // Delete copy
    PooledConnection(const PooledConnection&) = delete;
    PooledConnection& operator=(const PooledConnection&) = delete;

    /**
     * @brief Access the underlying connection
     */
    IDbConnection* get() const { return conn_.get(); }
    IDbConnection* operator->() const { return conn_.get(); }

    /**
     * @brief Check if connection is valid
     */
    bool is_valid() const { return conn_ != nullptr && conn_->is_connected(); }

private:
    std::unique_ptr<IDbConnection> conn_;
    ReturnFunc return_fn_;
};

} // namespace sqlproxy
