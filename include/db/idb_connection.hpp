#pragma once

#include "core/column_type.hpp"
#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace sqlproxy {

/**
 * @brief Result set from a query execution
 *
 * Returned by IDbConnection::execute().
 * Owns the result data (copied from native result handles).
 */
struct DbResultSet {
    bool success = false;
    std::string error_message;

    // For SELECT
    std::vector<std::string> column_names;
    std::vector<ColumnTypeInfo> column_types;
    std::vector<std::vector<std::string>> rows;

    // For DML
    uint64_t affected_rows = 0;

    // SELECT vs DML/DDL
    bool has_rows = false;
};

/**
 * @brief Abstract database connection
 *
 * Wraps a single native connection handle (PGconn*, MYSQL*, etc.).
 * Implementations are not thread-safe; thread safety comes from the pool.
 *
 * Does NOT expose native handles to prevent leaking backend types.
 */
class IDbConnection {
public:
    virtual ~IDbConnection() = default;

    /**
     * @brief Execute a SQL query or statement
     * @param sql SQL text
     * @return Result set with rows or affected count
     */
    [[nodiscard]] virtual DbResultSet execute(const std::string& sql) = 0;

    /**
     * @brief Check if the connection is healthy
     * @param health_check_query SQL to run (e.g., "SELECT 1")
     * @return true if connection is usable
     */
    [[nodiscard]] virtual bool is_healthy(const std::string& health_check_query) = 0;

    /**
     * @brief Check if connection is in a valid state (connected)
     */
    [[nodiscard]] virtual bool is_connected() const = 0;

    /**
     * @brief Set query timeout for subsequent queries
     * @param timeout_ms Timeout in milliseconds (0 = no timeout)
     * @return true if timeout was set successfully
     *
     * PostgreSQL: SET statement_timeout = N
     * MySQL: SET SESSION max_execution_time = N
     */
    virtual bool set_query_timeout(uint32_t timeout_ms) = 0;

    /**
     * @brief Close the connection and release resources
     */
    virtual void close() = 0;
};

} // namespace sqlproxy
