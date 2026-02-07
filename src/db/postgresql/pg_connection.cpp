#include "db/postgresql/pg_connection.hpp"
#include "core/utils.hpp"
#include <cstring>
#include <format>

namespace sqlproxy {

// ============================================================================
// PgConnection
// ============================================================================

PgConnection::PgConnection(PGconn* conn)
    : conn_(conn) {}

PgConnection::~PgConnection() {
    close();
}

DbResultSet PgConnection::execute(const std::string& sql) {
    if (!conn_) {
        return {false, "Connection is null", {}, {}, {}, 0, false};
    }

    PGresult* res = PQexec(conn_, sql.c_str());

    if (!res) {
        return {false, PQerrorMessage(conn_), {}, {}, {}, 0, false};
    }

    ExecStatusType status = PQresultStatus(res);

    if (status == PGRES_TUPLES_OK) {
        auto result = process_tuples_result(res);
        PQclear(res);
        return result;
    }

    if (status == PGRES_COMMAND_OK) {
        auto result = process_command_result(res);
        PQclear(res);
        return result;
    }

    // Error case
    std::string error = PQerrorMessage(conn_);
    PQclear(res);
    return {false, error, {}, {}, {}, 0, false};
}

bool PgConnection::is_healthy(const std::string& health_check_query) {
    if (!conn_) {
        return false;
    }

    if (PQstatus(conn_) != CONNECTION_OK) {
        return false;
    }

    PGresult* res = PQexec(conn_, health_check_query.c_str());
    if (!res) {
        return false;
    }

    ExecStatusType status = PQresultStatus(res);
    PQclear(res);

    return (status == PGRES_TUPLES_OK || status == PGRES_COMMAND_OK);
}

bool PgConnection::is_connected() const {
    return conn_ != nullptr && PQstatus(conn_) == CONNECTION_OK;
}

bool PgConnection::set_query_timeout(uint32_t timeout_ms) {
    if (!conn_) {
        return false;
    }

    std::string timeout_sql = std::format("SET statement_timeout = {}", timeout_ms);

    PGresult* res = PQexec(conn_, timeout_sql.c_str());
    if (!res) {
        return false;
    }

    bool success = (PQresultStatus(res) == PGRES_COMMAND_OK);
    PQclear(res);
    return success;
}

void PgConnection::close() {
    if (conn_) {
        PQfinish(conn_);
        conn_ = nullptr;
    }
}

DbResultSet PgConnection::process_tuples_result(PGresult* res) {
    DbResultSet result;
    result.success = true;
    result.has_rows = true;

    int ncols = PQnfields(res);
    for (int i = 0; i < ncols; i++) {
        result.column_names.push_back(PQfname(res, i));

        // Store PG OID as vendor_type_id for now
        // Full GenericColumnType mapping happens in pg_type_map
        Oid type_oid = PQftype(res, i);
        result.column_types.emplace_back(
            GenericColumnType::UNKNOWN, static_cast<uint32_t>(type_oid), "");
    }

    int nrows = PQntuples(res);
    result.rows.reserve(nrows);

    for (int i = 0; i < nrows; i++) {
        std::vector<std::string> row;
        row.reserve(ncols);
        for (int j = 0; j < ncols; j++) {
            const char* val = PQgetvalue(res, i, j);
            row.push_back(val ? val : "");
        }
        result.rows.push_back(std::move(row));
    }

    return result;
}

DbResultSet PgConnection::process_command_result(PGresult* res) {
    DbResultSet result;
    result.success = true;
    result.has_rows = false;

    const char* affected = PQcmdTuples(res);
    if (affected && std::strlen(affected) > 0) {
        result.affected_rows = std::stoull(affected);
    }

    return result;
}

// ============================================================================
// PgConnectionFactory
// ============================================================================

std::unique_ptr<IDbConnection> PgConnectionFactory::create(
    const std::string& connection_string) {

    PGconn* conn = PQconnectdb(connection_string.c_str());

    if (!conn) {
        utils::log::error("Failed to allocate PGconn");
        return nullptr;
    }

    if (PQstatus(conn) != CONNECTION_OK) {
        utils::log::error(std::format("Failed to connect: {}", PQerrorMessage(conn)));
        PQfinish(conn);
        return nullptr;
    }

    return std::make_unique<PgConnection>(conn);
}

} // namespace sqlproxy
