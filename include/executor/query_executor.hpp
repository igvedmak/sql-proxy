#pragma once

#include "core/types.hpp"
#include "executor/circuit_breaker.hpp"
#include "executor/connection_pool.hpp"
#include <string>
#include <memory>

namespace sqlproxy {

/**
 * @brief Query executor - executes SQL against PostgreSQL
 *
 * Handles statement branching:
 * - SELECT: Execute + fetch results
 * - DML: Execute + capture affected_rows
 * - DDL: Execute + trigger schema invalidation
 *
 * Uses connection pool for multi-user support and resource management.
 */
class QueryExecutor {
public:
    /**
     * @brief Configuration for query executor
     */
    struct Config {
        uint32_t query_timeout_ms;      // Query timeout in milliseconds
        uint32_t max_result_rows;       // Maximum rows to fetch for SELECT
        bool enable_query_timeout;      // Enable/disable timeout

        Config()
            : query_timeout_ms(30000),  // 30 seconds default
              max_result_rows(10000),   // 10K rows default
              enable_query_timeout(true) {}
    };

    /**
     * @brief Construct executor with connection pool
     * @param pool Connection pool for database
     * @param circuit_breaker Circuit breaker for this database
     * @param config Executor configuration
     */
    explicit QueryExecutor(
        std::shared_ptr<ConnectionPool> pool,
        std::shared_ptr<CircuitBreaker> circuit_breaker = nullptr,
        const Config& config = Config()
    );

    ~QueryExecutor();

    /**
     * @brief Execute SQL statement
     * @param sql SQL query
     * @param stmt_type Statement type (for branching)
     * @return Query result
     */
    QueryResult execute(const std::string& sql, StatementType stmt_type);

private:
    /**
     * @brief Execute SELECT query
     */
    QueryResult execute_select(const std::string& sql);

    /**
     * @brief Execute DML statement
     */
    QueryResult execute_dml(const std::string& sql);

    /**
     * @brief Execute DDL statement
     */
    QueryResult execute_ddl(const std::string& sql);

    /**
     * @brief Set query timeout on connection
     * @param conn PostgreSQL connection
     * @return true if successful
     */
    bool set_query_timeout(void* conn);

    std::shared_ptr<ConnectionPool> pool_;
    std::shared_ptr<CircuitBreaker> circuit_breaker_;
    Config config_;
};

} // namespace sqlproxy
