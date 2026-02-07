#pragma once

#include "db/iquery_executor.hpp"
#include "db/iconnection_pool.hpp"
#include "executor/circuit_breaker.hpp"
#include <memory>
#include <cstdint>
#include <functional>

namespace sqlproxy {

/**
 * @brief Database-agnostic query executor
 *
 * Uses IConnectionPool to acquire connections and IDbConnection::execute()
 * to run queries. Circuit breaker integration, statement branching, and
 * timing are all handled here — no per-backend executor needed.
 */
class GenericQueryExecutor : public IQueryExecutor {
public:
    struct Config {
        uint32_t query_timeout_ms = 30000;
        uint32_t max_result_rows = 10000;
        bool enable_query_timeout = true;
    };

    GenericQueryExecutor(
        std::shared_ptr<IConnectionPool> pool,
        std::shared_ptr<CircuitBreaker> circuit_breaker,
        const Config& config);

    GenericQueryExecutor(
        std::shared_ptr<IConnectionPool> pool,
        std::shared_ptr<CircuitBreaker> circuit_breaker = nullptr)
        : GenericQueryExecutor(std::move(pool), std::move(circuit_breaker), Config{}) {}

    ~GenericQueryExecutor() override = default;

    QueryResult execute(const std::string& sql, StatementType stmt_type) override;

private:
    QueryResult execute_select(const std::string& sql);
    QueryResult execute_dml(const std::string& sql);
    QueryResult execute_ddl(const std::string& sql);

    std::shared_ptr<IConnectionPool> pool_;
    std::shared_ptr<CircuitBreaker> circuit_breaker_;
    Config config_;

public:
    /**
     * @brief Set callback to fire after successful DDL (e.g., schema cache invalidation)
     */
    void set_on_ddl_success(std::function<void()> callback) {
        on_ddl_success_ = std::move(callback);
    }

private:
    std::function<void()> on_ddl_success_;
};

} // namespace sqlproxy
