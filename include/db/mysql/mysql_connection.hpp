#pragma once

#include "db/idb_connection.hpp"
#include "db/iconnection_factory.hpp"
#include <mysql/mysql.h>
#include <string>

namespace sqlproxy {

/**
 * @brief MySQL connection implementing IDbConnection
 *
 * Wraps MYSQL* handle (MariaDB Connector/C or libmysqlclient).
 * All MySQL C API calls are encapsulated here.
 */
class MysqlConnection : public IDbConnection {
public:
    explicit MysqlConnection(MYSQL* conn);
    ~MysqlConnection() override;

    MysqlConnection(const MysqlConnection&) = delete;
    MysqlConnection& operator=(const MysqlConnection&) = delete;

    DbResultSet execute(const std::string& sql) override;
    bool is_healthy(const std::string& health_check_query) override;
    bool is_connected() const override;
    bool set_query_timeout(uint32_t timeout_ms) override;
    void close() override;

private:
    DbResultSet process_result_set(MYSQL_RES* res);
    DbResultSet process_affected_rows();

    MYSQL* conn_;
};

/**
 * @brief MySQL connection factory
 *
 * Creates MysqlConnection instances using mysql_real_connect.
 * Parses connection strings in URI format:
 *   mysql://user:password@host:port/database
 */
class MysqlConnectionFactory : public IConnectionFactory {
public:
    std::unique_ptr<IDbConnection> create(const std::string& connection_string) override;

private:
    struct ConnParams {
        std::string host;
        std::string user;
        std::string password;
        std::string database;
        unsigned int port = 3306;
    };

    static ConnParams parse_connection_string(const std::string& conn_str);
};

} // namespace sqlproxy
