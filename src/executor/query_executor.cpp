#include "executor/query_executor.hpp"
#include "core/utils.hpp"
#include <libpq-fe.h>
#include <algorithm>
#include <cstring>
#include <format>

namespace sqlproxy {

namespace {

/**
 * @brief Classify a database error message into an error category.
 *
 * Infrastructure: connection-level failures that indicate the DB is unavailable.
 * Transient: temporary lock/serialization issues that may resolve on retry.
 * Application: everything else (syntax errors, constraint violations, etc.)
 */
FailureCategory classify_db_error(const std::string& error_msg) {
    std::string lower = error_msg;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // Infrastructure patterns (connection-level failures)
    static const std::vector<std::string> infra_patterns = {
        "connection refused", "could not connect", "server closed",
        "timeout", "host not found", "no route", "connection reset",
        "broken pipe", "could not send", "could not receive",
        "failed to acquire database connection"
    };
    for (const auto& p : infra_patterns) {
        if (lower.find(p) != std::string::npos) return FailureCategory::INFRASTRUCTURE;
    }

    // Transient patterns (retryable)
    static const std::vector<std::string> transient_patterns = {
        "deadlock", "lock timeout", "serialization failure", "could not obtain lock"
    };
    for (const auto& p : transient_patterns) {
        if (lower.find(p) != std::string::npos) return FailureCategory::TRANSIENT;
    }

    // Default: application errors (syntax, constraint, permission, etc.)
    return FailureCategory::APPLICATION;
}

} // anonymous namespace

QueryExecutor::QueryExecutor(
    std::shared_ptr<ConnectionPool> pool,
    std::shared_ptr<CircuitBreaker> circuit_breaker,
    const Config& config)
    : pool_(std::move(pool)),
      circuit_breaker_(std::move(circuit_breaker)),
      config_(config) {
    // Connection pool is now managed externally
}

QueryExecutor::~QueryExecutor() {
    // Connection pool manages lifecycle
}

QueryResult QueryExecutor::execute(const std::string& sql, StatementType stmt_type) {
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
        // Branch based on statement type
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

        // Record success/failure in circuit breaker
        if (circuit_breaker_) {
            if (result.success) {
                circuit_breaker_->record_success();
            } else {
                circuit_breaker_->record_failure(
                    classify_db_error(result.error_message));
            }
        }

    } catch (const std::exception& e) {
        result.success = false;
        result.error_code = ErrorCode::DATABASE_ERROR;
        result.error_message = std::format("Database error: {}", e.what());
        result.execution_time = timer.elapsed_us();

        if (circuit_breaker_) {
            // Exceptions from execute are always infrastructure failures
            circuit_breaker_->record_failure(FailureCategory::INFRASTRUCTURE);
        }
    }

    return result;
}

QueryResult QueryExecutor::execute_select(const std::string& sql) {
    QueryResult result;

    // Acquire connection from pool
    auto conn_handle = pool_->acquire(std::chrono::milliseconds{5000});
    if (!conn_handle || !conn_handle->is_valid()) {
        result.success = false;
        result.error_code = ErrorCode::DATABASE_ERROR;
        result.error_message = "Failed to acquire database connection from pool";
        return result;
    }

    PGconn* conn = conn_handle->get();

    // Set query timeout
    if (config_.enable_query_timeout) {
        if (!set_query_timeout(conn)) {
            // Log warning but continue - timeout setting is not critical
        }
    }

    // Execute query
    PGresult* res = PQexec(conn, sql.c_str());

    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        result.success = false;
        result.error_code = ErrorCode::DATABASE_ERROR;
        result.error_message = PQerrorMessage(conn);
        if (res) PQclear(res);
        return result;
    }

    // Extract column names and type OIDs
    int ncols = PQnfields(res);
    for (int i = 0; i < ncols; i++) {
        result.column_names.push_back(PQfname(res, i));
        result.column_type_oids.push_back(PQftype(res, i));  // For PII classification
    }

    // Extract rows
    const int nrows = PQntuples(res);

    // Check max rows limit
    if (config_.max_result_rows > 0 && static_cast<uint32_t>(nrows) > config_.max_result_rows) {
        result.success = false;
        result.error_code = ErrorCode::RESULT_TOO_LARGE;
        result.error_message = std::format("Result set exceeds max_result_rows limit ({} rows)", config_.max_result_rows);
        PQclear(res);
        return result;
    }

    for (int i = 0; i < nrows; i++) {
        std::vector<std::string> row;
        for (int j = 0; j < ncols; j++) {
            const char* val = PQgetvalue(res, i, j);
            row.push_back(val ? val : "");
        }
        result.rows.emplace_back(std::move(row));
    }

    PQclear(res);

    result.success = true;
    return result;
}

QueryResult QueryExecutor::execute_dml(const std::string& sql) {
    QueryResult result;

    // Acquire connection from pool
    auto conn_handle = pool_->acquire(std::chrono::milliseconds{5000});
    if (!conn_handle || !conn_handle->is_valid()) {
        result.success = false;
        result.error_code = ErrorCode::DATABASE_ERROR;
        result.error_message = "Failed to acquire database connection from pool";
        return result;
    }

    PGconn* conn = conn_handle->get();

    // Execute DML statement
    PGresult* res = PQexec(conn, sql.c_str());

    if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) {
        result.success = false;
        result.error_code = ErrorCode::DATABASE_ERROR;
        result.error_message = PQerrorMessage(conn);
        if (res) PQclear(res);
        return result;
    }

    // Get affected rows count
    const char* affected = PQcmdTuples(res);
    result.affected_rows = utils::parse_int<uint64_t>(affected);

    PQclear(res);

    result.success = true;
    return result;
}

QueryResult QueryExecutor::execute_ddl(const std::string& sql) {
    QueryResult result;

    // Acquire connection from pool
    auto conn_handle = pool_->acquire(std::chrono::milliseconds{5000});
    if (!conn_handle || !conn_handle->is_valid()) {
        result.success = false;
        result.error_code = ErrorCode::DATABASE_ERROR;
        result.error_message = "Failed to acquire database connection from pool";
        return result;
    }

    PGconn* conn = conn_handle->get();

    // Execute DDL statement
    PGresult* res = PQexec(conn, sql.c_str());

    if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) {
        result.success = false;
        result.error_code = ErrorCode::DATABASE_ERROR;
        result.error_message = PQerrorMessage(conn);
        if (res) PQclear(res);
        return result;
    }

    PQclear(res);

    // Notify schema cache (async) after successful DDL
    if (on_ddl_success_) {
        on_ddl_success_();
    }

    result.success = true;
    result.affected_rows = 0;
    return result;
}

bool QueryExecutor::set_query_timeout(void* conn_ptr) {
    PGconn* conn = static_cast<PGconn*>(conn_ptr);

    // Set statement_timeout in milliseconds
    const std::string timeout_sql = std::format("SET statement_timeout = {}", config_.query_timeout_ms);

    PGresult* res = PQexec(conn, timeout_sql.c_str());
    if (!res) {
        return false;
    }

    const bool success = (PQresultStatus(res) == PGRES_COMMAND_OK);
    PQclear(res);

    return success;
}

} // namespace sqlproxy
