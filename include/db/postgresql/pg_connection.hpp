#pragma once

#include "db/idb_connection.hpp"
#include "db/iconnection_factory.hpp"
#include <libpq-fe.h>
#include <string>

namespace sqlproxy {

/**
 * @brief PostgreSQL connection implementing IDbConnection
 *
 * Wraps PGconn* and provides database-agnostic interface.
 * All libpq calls are encapsulated here.
 */
class PgConnection : public IDbConnection {
public:
    /**
     * @brief Construct from existing PGconn* (takes ownership)
     */
    explicit PgConnection(PGconn* conn);

    ~PgConnection() override;

    PgConnection(const PgConnection&) = delete;
    PgConnection& operator=(const PgConnection&) = delete;

    DbResultSet execute(const std::string& sql) override;
    bool is_healthy(const std::string& health_check_query) override;
    bool is_connected() const override;
    bool set_query_timeout(uint32_t timeout_ms) override;
    void close() override;

private:
    /**
     * @brief Process a SELECT result (PGRES_TUPLES_OK)
     */
    DbResultSet process_tuples_result(PGresult* res);

    /**
     * @brief Process a command result (PGRES_COMMAND_OK)
     */
    DbResultSet process_command_result(PGresult* res);

    PGconn* conn_;
};

/**
 * @brief PostgreSQL connection factory
 *
 * Creates PgConnection instances using PQconnectdb.
 */
class PgConnectionFactory : public IConnectionFactory {
public:
    std::unique_ptr<IDbConnection> create(const std::string& connection_string) override;
};

} // namespace sqlproxy
