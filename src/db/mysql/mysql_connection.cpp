#include "db/mysql/mysql_connection.hpp"
#include "db/mysql/mysql_type_map.hpp"
#include "core/utils.hpp"
#include <cstring>
#include <format>

namespace sqlproxy {

MysqlConnection::MysqlConnection(MYSQL* conn)
    : conn_(conn) {}

MysqlConnection::~MysqlConnection() {
    close();
}

DbResultSet MysqlConnection::execute(const std::string& sql) {
    DbResultSet result;

    if (!conn_) {
        result.success = false;
        result.error_message = "Connection is null";
        return result;
    }

    if (mysql_query(conn_, sql.c_str()) != 0) {
        result.success = false;
        result.error_message = mysql_error(conn_);
        return result;
    }

    // Check if the query produced a result set
    MYSQL_RES* res = mysql_store_result(conn_);
    if (res) {
        result = process_result_set(res);
        mysql_free_result(res);
    } else {
        // No result set: either DML/DDL or error
        if (mysql_field_count(conn_) == 0) {
            // DML/DDL - no result set expected
            result = process_affected_rows();
        } else {
            // Error: expected result set but got none
            result.success = false;
            result.error_message = mysql_error(conn_);
        }
    }

    return result;
}

DbResultSet MysqlConnection::process_result_set(MYSQL_RES* res) {
    DbResultSet result;
    result.success = true;
    result.has_rows = true;

    // Extract column metadata
    unsigned int num_fields = mysql_num_fields(res);
    MYSQL_FIELD* fields = mysql_fetch_fields(res);

    result.column_names.reserve(num_fields);
    result.column_types.reserve(num_fields);

    for (unsigned int i = 0; i < num_fields; ++i) {
        result.column_names.emplace_back(fields[i].name);
        result.column_types.push_back(
            MysqlTypeMap::build_type_info(fields[i].type, fields[i].name));
    }

    // Extract rows
    MYSQL_ROW row;
    unsigned long* lengths;
    while ((row = mysql_fetch_row(res)) != nullptr) {
        lengths = mysql_fetch_lengths(res);
        std::vector<std::string> row_data;
        row_data.reserve(num_fields);

        for (unsigned int i = 0; i < num_fields; ++i) {
            if (row[i]) {
                row_data.emplace_back(row[i], lengths[i]);
            } else {
                row_data.emplace_back("");  // NULL → empty string
            }
        }

        result.rows.push_back(std::move(row_data));
    }

    result.affected_rows = result.rows.size();
    return result;
}

DbResultSet MysqlConnection::process_affected_rows() {
    DbResultSet result;
    result.success = true;
    result.has_rows = false;
    result.affected_rows = static_cast<uint64_t>(mysql_affected_rows(conn_));
    return result;
}

bool MysqlConnection::is_healthy(const std::string& health_check_query) {
    if (!conn_) {
        return false;
    }

    // Fast ping check
    if (mysql_ping(conn_) != 0) {
        return false;
    }

    // Run health check query if provided
    if (!health_check_query.empty()) {
        if (mysql_query(conn_, health_check_query.c_str()) != 0) {
            return false;
        }
        MYSQL_RES* res = mysql_store_result(conn_);
        if (res) {
            mysql_free_result(res);
        }
    }

    return true;
}

bool MysqlConnection::is_connected() const {
    return conn_ != nullptr;
}

bool MysqlConnection::set_query_timeout(uint32_t timeout_ms) {
    if (!conn_) {
        return false;
    }

    // MySQL uses SET max_execution_time (MySQL 5.7.8+)
    std::string sql = std::format("SET SESSION max_execution_time = {}", timeout_ms);
    return mysql_query(conn_, sql.c_str()) == 0;
}

void MysqlConnection::close() {
    if (conn_) {
        mysql_close(conn_);
        conn_ = nullptr;
    }
}

// ============================================================================
// MysqlConnectionFactory
// ============================================================================

std::unique_ptr<IDbConnection> MysqlConnectionFactory::create(
    const std::string& connection_string) {

    auto params = parse_connection_string(connection_string);

    MYSQL* conn = mysql_init(nullptr);
    if (!conn) {
        utils::log::error("mysql_init failed");
        return nullptr;
    }

    // Enable auto-reconnect
    bool reconnect = true;
    mysql_options(conn, MYSQL_OPT_RECONNECT, &reconnect);

    // Set connection timeout (5 seconds)
    unsigned int timeout = 5;
    mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);

    // Set character set to UTF-8
    mysql_options(conn, MYSQL_SET_CHARSET_NAME, "utf8mb4");

    MYSQL* result = mysql_real_connect(
        conn,
        params.host.c_str(),
        params.user.c_str(),
        params.password.c_str(),
        params.database.c_str(),
        params.port,
        nullptr,  // unix socket
        0         // client flags
    );

    if (!result) {
        utils::log::error(std::format("MySQL connection failed: {}", mysql_error(conn)));
        mysql_close(conn);
        return nullptr;
    }

    return std::make_unique<MysqlConnection>(conn);
}

MysqlConnectionFactory::ConnParams MysqlConnectionFactory::parse_connection_string(
    const std::string& conn_str) {

    ConnParams params;
    params.host = "localhost";
    params.port = 3306;

    // Parse URI format: mysql://user:password@host:port/database
    std::string_view sv(conn_str);

    // Strip protocol prefix
    if (sv.starts_with("mysql://")) {
        sv.remove_prefix(8);
    } else if (sv.starts_with("mariadb://")) {
        sv.remove_prefix(10);
    }

    // Find @ separator between credentials and host
    size_t at_pos = sv.find('@');
    if (at_pos != std::string_view::npos) {
        std::string_view creds = sv.substr(0, at_pos);
        sv.remove_prefix(at_pos + 1);

        // Parse user:password
        size_t colon_pos = creds.find(':');
        if (colon_pos != std::string_view::npos) {
            params.user = std::string(creds.substr(0, colon_pos));
            params.password = std::string(creds.substr(colon_pos + 1));
        } else {
            params.user = std::string(creds);
        }
    }

    // Parse host:port/database
    size_t slash_pos = sv.find('/');
    std::string_view host_port;
    if (slash_pos != std::string_view::npos) {
        host_port = sv.substr(0, slash_pos);
        params.database = std::string(sv.substr(slash_pos + 1));
    } else {
        host_port = sv;
    }

    // Parse host:port
    size_t colon_pos = host_port.find(':');
    if (colon_pos != std::string_view::npos) {
        params.host = std::string(host_port.substr(0, colon_pos));
        std::string port_str(host_port.substr(colon_pos + 1));
        try {
            params.port = static_cast<unsigned int>(std::stoi(port_str));
        } catch (...) {
            params.port = 3306;
        }
    } else {
        params.host = std::string(host_port);
    }

    return params;
}

} // namespace sqlproxy
