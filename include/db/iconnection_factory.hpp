#pragma once

#include "db/idb_connection.hpp"
#include <memory>
#include <string>

namespace sqlproxy {

/**
 * @brief Abstract factory for creating database connections
 *
 * Each backend provides its own factory that wraps the native
 * connection function (PQconnectdb, mysql_real_connect, etc.).
 */
class IConnectionFactory {
public:
    virtual ~IConnectionFactory() = default;

    /**
     * @brief Create a new database connection
     * @param connection_string Backend-specific connection string
     * @return New connection, or nullptr on failure
     */
    [[nodiscard]] virtual std::unique_ptr<IDbConnection> create(
        const std::string& connection_string) = 0;
};

} // namespace sqlproxy
