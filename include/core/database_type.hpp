#pragma once

#include <string>
#include <stdexcept>
#include <algorithm>

namespace sqlproxy {

enum class DatabaseType {
    POSTGRESQL,
    MYSQL,
};

[[nodiscard]] inline const char* database_type_to_string(DatabaseType type) {
    switch (type) {
        case DatabaseType::POSTGRESQL: return "postgresql";
        case DatabaseType::MYSQL: return "mysql";
        default: return "unknown";
    }
}

[[nodiscard]] inline DatabaseType parse_database_type(const std::string& type_str) {
    std::string lower = type_str;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    if (lower == "postgresql" || lower == "postgres" || lower == "pg") {
        return DatabaseType::POSTGRESQL;
    }
    if (lower == "mysql" || lower == "mariadb") {
        return DatabaseType::MYSQL;
    }

    throw std::runtime_error("Unknown database type: " + type_str);
}

} // namespace sqlproxy
