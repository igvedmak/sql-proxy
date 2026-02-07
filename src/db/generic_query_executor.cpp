#include "db/generic_query_executor.hpp"
#include "db/pooled_connection.hpp"
#include "core/utils.hpp"
#include <format>

namespace sqlproxy {

GenericQueryExecutor::GenericQueryExecutor(
    std::shared_ptr<IConnectionPool> pool,
    std::shared_ptr<CircuitBreaker> circuit_breaker,
    const Config& config)
    : pool_(std::move(pool)),
      circuit_breaker_(std::move(circuit_breaker)),
      config_(config) {}

QueryResult GenericQueryExecutor::execute(const std::string& sql, StatementType stmt_type) {
    // Check circuit breaker
    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        QueryResult result;
        result.success = false;
        result.error_code = ErrorCode::CIRCUIT_OPEN;
        result.error_message = std::format("Circuit breaker is OPEN for database: {}", circuit_breaker_->name());
        return result;
    }

    utils::Timer timer;
    QueryResult result;

    try {
        if (stmt_type == StatementType::SELECT) {
            result = execute_select(sql);
        } else if (stmt_mask::test(stmt_type, stmt_mask::kDML)) {
            result = execute_dml(sql);
        } else if (stmt_mask::test(stmt_type, stmt_mask::kDDL)) {
            result = execute_ddl(sql);
        } else {
            result.success = false;
            result.error_code = ErrorCode::INTERNAL_ERROR;
            result.error_message = "Unsupported statement type";
        }

        result.execution_time = timer.elapsed_us();

        if (circuit_breaker_) {
            if (result.success) {
                circuit_breaker_->record_success();
            } else {
                circuit_breaker_->record_failure();
            }
        }

    } catch (const std::exception& e) {
        result.success = false;
        result.error_code = ErrorCode::DATABASE_ERROR;
        result.error_message = std::format("Database error: {}", e.what());
        result.execution_time = timer.elapsed_us();

        if (circuit_breaker_) {
            circuit_breaker_->record_failure();
        }
    }

    return result;
}

QueryResult GenericQueryExecutor::execute_select(const std::string& sql) {
    QueryResult result;

    auto conn_handle = pool_->acquire(std::chrono::milliseconds{5000});
    if (!conn_handle || !conn_handle->is_valid()) {
        result.success = false;
        result.error_code = ErrorCode::DATABASE_ERROR;
        result.error_message = "Failed to acquire database connection from pool";
        return result;
    }

    auto* conn = conn_handle->get();

    // Set query timeout
    if (config_.enable_query_timeout) {
        conn->set_query_timeout(config_.query_timeout_ms);
    }

    // Execute via IDbConnection
    auto db_result = conn->execute(sql);

    if (!db_result.success) {
        result.success = false;
        result.error_code = ErrorCode::DATABASE_ERROR;
        result.error_message = db_result.error_message;
        return result;
    }

    // Check max rows limit
    if (config_.max_result_rows > 0 &&
        db_result.rows.size() > config_.max_result_rows) {
        result.success = false;
        result.error_code = ErrorCode::RESULT_TOO_LARGE;
        result.error_message = std::format("Result set exceeds max_result_rows limit ({} rows)", config_.max_result_rows);
        return result;
    }

    // Convert DbResultSet → QueryResult
    result.success = true;
    result.column_names = std::move(db_result.column_names);
    result.rows = std::move(db_result.rows);

    // Map column types: extract vendor_type_id for backward compat
    result.column_type_oids.reserve(db_result.column_types.size());
    for (const auto& ct : db_result.column_types) {
        result.column_type_oids.push_back(ct.vendor_type_id);
    }

    return result;
}

QueryResult GenericQueryExecutor::execute_dml(const std::string& sql) {
    QueryResult result;

    auto conn_handle = pool_->acquire(std::chrono::milliseconds{5000});
    if (!conn_handle || !conn_handle->is_valid()) {
        result.success = false;
        result.error_code = ErrorCode::DATABASE_ERROR;
        result.error_message = "Failed to acquire database connection from pool";
        return result;
    }

    auto db_result = conn_handle->get()->execute(sql);

    if (!db_result.success) {
        result.success = false;
        result.error_code = ErrorCode::DATABASE_ERROR;
        result.error_message = db_result.error_message;
        return result;
    }

    result.success = true;
    result.affected_rows = db_result.affected_rows;
    return result;
}

QueryResult GenericQueryExecutor::execute_ddl(const std::string& sql) {
    QueryResult result;

    auto conn_handle = pool_->acquire(std::chrono::milliseconds{5000});
    if (!conn_handle || !conn_handle->is_valid()) {
        result.success = false;
        result.error_code = ErrorCode::DATABASE_ERROR;
        result.error_message = "Failed to acquire database connection from pool";
        return result;
    }

    auto db_result = conn_handle->get()->execute(sql);

    if (!db_result.success) {
        result.success = false;
        result.error_code = ErrorCode::DATABASE_ERROR;
        result.error_message = db_result.error_message;
        return result;
    }

    result.success = true;
    result.affected_rows = 0;
    return result;
}

} // namespace sqlproxy
