#pragma once

#include <string>
#include <string_view>
#include <stdexcept>
#include <algorithm>
#include <format>
#include <unordered_map>

namespace sqlproxy {

namespace keys {
    inline constexpr std::string_view POSTGRES = "postgres";
    inline constexpr std::string_view POSTGRESQL = "postgresql";
    inline constexpr std::string_view PG = "pg";
    inline constexpr std::string_view MYSQL = "mysql";
    inline constexpr std::string_view MARIADB = "mariadb";
}

enum class DatabaseType {
    POSTGRESQL,
    MYSQL,
};

[[nodiscard]] inline std::string_view database_type_to_string(DatabaseType type) {
    switch (type) {
        case DatabaseType::POSTGRESQL: return keys::POSTGRESQL;
        case DatabaseType::MYSQL: return keys::MYSQL;
        default: return "unknown";
    }
}

[[nodiscard]] inline DatabaseType parse_database_type(std::string_view type_str) {
    // 1. Static map for O(1) lookup. 
    // Using string_view keys means NO heap allocations during lookup.
    static const std::unordered_map<std::string_view, DatabaseType> lookup = {
        {keys::POSTGRESQL, DatabaseType::POSTGRESQL},
        {keys::POSTGRES,   DatabaseType::POSTGRESQL},
        {keys::PG,         DatabaseType::POSTGRESQL},
        {keys::MYSQL,      DatabaseType::MYSQL},
        {keys::MARIADB,    DatabaseType::MYSQL}
    };

    // 2. Direct lookup
    if (const auto it = lookup.find(type_str); it != lookup.end()) {
        return it->second;
    }

    // 3. Fallback: Case-insensitive check (only if direct lookup fails)
    // This avoids lowercase conversion for the "happy path"
    for (const auto& [key, value] : lookup) {
        if (key.size() == type_str.size()) {
            const bool match = std::equal(key.begin(), key.end(), type_str.begin(),
                [](char a, char b) { return std::tolower(a) == std::tolower(b); });
            if (match) return value;
        }
    }

    throw std::runtime_error("Unknown database type: " + std::format("{}", type_str));
}

} // namespace sqlproxy
