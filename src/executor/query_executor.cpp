#include "executor/query_executor.hpp"
#include "core/utils.hpp"
#include <libpq-fe.h>
#include <cstring>

namespace sqlproxy {

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
        result.error_message = "Circuit breaker is OPEN for database: " + circuit_breaker_->name();
        return result;
    }

    utils::Timer timer;
    QueryResult result;

    try {
        // Branch based on statement type
        switch (stmt_type) {
            case StatementType::SELECT:
                result = execute_select(sql);
                break;

            case StatementType::INSERT:
            case StatementType::UPDATE:
            case StatementType::DELETE:
                result = execute_dml(sql);
                break;

            case StatementType::CREATE_TABLE:
            case StatementType::ALTER_TABLE:
            case StatementType::DROP_TABLE:
            case StatementType::CREATE_INDEX:
            case StatementType::DROP_INDEX:
            case StatementType::TRUNCATE:
                result = execute_ddl(sql);
                break;

            default:
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
                circuit_breaker_->record_failure();
            }
        }

    } catch (const std::exception& e) {
        result.success = false;
        result.error_code = ErrorCode::DATABASE_ERROR;
        result.error_message = std::string("Database error: ") + e.what();
        result.execution_time = timer.elapsed_us();

        if (circuit_breaker_) {
            circuit_breaker_->record_failure();
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
    int nrows = PQntuples(res);

    // Check max rows limit
    if (config_.max_result_rows > 0 && static_cast<uint32_t>(nrows) > config_.max_result_rows) {
        result.success = false;
        result.error_code = ErrorCode::RESULT_TOO_LARGE;
        result.error_message = "Result set exceeds max_result_rows limit (" +
                              std::to_string(config_.max_result_rows) + " rows)";
        PQclear(res);
        return result;
    }

    for (int i = 0; i < nrows; i++) {
        std::vector<std::string> row;
        for (int j = 0; j < ncols; j++) {
            const char* val = PQgetvalue(res, i, j);
            row.push_back(val ? val : "");
        }
        result.rows.push_back(std::move(row));
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
    if (affected && strlen(affected) > 0) {
        result.affected_rows = std::stoull(affected);
    } else {
        result.affected_rows = 0;
    }

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

    // TODO: Trigger schema cache invalidation after successful DDL
    // When schema cache is implemented, hook here:
    // if (schema_cache_) {
    //     schema_cache_->invalidate_async();
    // }

    result.success = true;
    result.affected_rows = 0;
    return result;
}

bool QueryExecutor::set_query_timeout(void* conn_ptr) {
    PGconn* conn = static_cast<PGconn*>(conn_ptr);

    // Set statement_timeout in milliseconds
    std::string timeout_sql = "SET statement_timeout = " +
                             std::to_string(config_.query_timeout_ms);

    PGresult* res = PQexec(conn, timeout_sql.c_str());
    if (!res) {
        return false;
    }

    bool success = (PQresultStatus(res) == PGRES_COMMAND_OK);
    PQclear(res);

    return success;
}

} // namespace sqlproxy
