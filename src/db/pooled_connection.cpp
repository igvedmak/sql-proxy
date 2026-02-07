#include "db/pooled_connection.hpp"

namespace sqlproxy {

PooledConnection::PooledConnection(std::unique_ptr<IDbConnection> conn, ReturnFunc return_fn)
    : conn_(std::move(conn)), return_fn_(std::move(return_fn)) {}

PooledConnection::~PooledConnection() {
    if (conn_ && return_fn_) {
        return_fn_(std::move(conn_));
    }
}

PooledConnection::PooledConnection(PooledConnection&& other) noexcept
    : conn_(std::move(other.conn_)), return_fn_(std::move(other.return_fn_)) {}

PooledConnection& PooledConnection::operator=(PooledConnection&& other) noexcept {
    if (this != &other) {
        // Return current connection before taking new one
        if (conn_ && return_fn_) {
            return_fn_(std::move(conn_));
        }
        conn_ = std::move(other.conn_);
        return_fn_ = std::move(other.return_fn_);
    }
    return *this;
}

} // namespace sqlproxy
