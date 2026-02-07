#include "db/mysql/mysql_schema_loader.hpp"
#include "db/mysql/mysql_connection.hpp"
#include "db/mysql/mysql_type_map.hpp"
#include "core/utils.hpp"
#include <algorithm>

namespace sqlproxy {

std::shared_ptr<SchemaMap> MysqlSchemaLoader::load_schema(
    const std::string& conn_string) {

    auto cache = std::make_shared<SchemaMap>();

    // Create a temporary connection for schema loading
    MysqlConnectionFactory factory;
    auto conn = factory.create(conn_string);
    if (!conn) {
        return cache;
    }

    // Query information_schema for column metadata
    static const std::string SCHEMA_QUERY =
        "SELECT "
        "    TABLE_SCHEMA, "
        "    TABLE_NAME, "
        "    COLUMN_NAME, "
        "    DATA_TYPE, "
        "    IS_NULLABLE, "
        "    COLUMN_DEFAULT, "
        "    ORDINAL_POSITION "
        "FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys') "
        "ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION";

    auto result = conn->execute(SCHEMA_QUERY);
    if (!result.success || !result.has_rows) {
        return cache;
    }

    // Track current table for consecutive column accumulation
    std::string current_key;
    std::shared_ptr<TableMetadata> current_table;

    for (const auto& row : result.rows) {
        if (row.size() < 5) continue;

        std::string schema_name = utils::to_lower(row[0]);
        std::string table_name  = utils::to_lower(row[1]);
        std::string column_name = utils::to_lower(row[2]);
        std::string data_type   = utils::to_lower(row[3]);
        std::string nullable_str = row[4];

        // Build map key
        std::string key;
        key.reserve(schema_name.size() + 1 + table_name.size());
        key = schema_name;
        key += '.';
        key += table_name;

        if (key != current_key) {
            if (current_table) {
                (*cache)[current_key] = std::move(current_table);
            }

            auto [it, inserted] = cache->try_emplace(key, nullptr);
            if (!inserted && it->second) {
                current_table = it->second;
            } else {
                current_table = std::make_shared<TableMetadata>();
                current_table->schema = schema_name;
                current_table->name = table_name;
                current_table->version = 0;
            }

            current_key = std::move(key);
        }

        // Build ColumnMetadata
        ColumnMetadata col;
        col.name = std::move(column_name);
        col.type = std::move(data_type);
        col.type_oid = 0;  // MySQL doesn't use OIDs
        col.nullable = (nullable_str == "YES" || nullable_str == "yes");
        col.is_primary_key = false;

        const size_t col_index = current_table->columns.size();
        current_table->column_index[col.name] = col_index;
        current_table->columns.push_back(std::move(col));
    }

    // Save last table
    if (current_table && !current_key.empty()) {
        (*cache)[current_key] = std::move(current_table);
    }

    // Second pass: load primary key info from KEY_COLUMN_USAGE
    static const std::string PK_QUERY =
        "SELECT "
        "    TABLE_SCHEMA, "
        "    TABLE_NAME, "
        "    COLUMN_NAME "
        "FROM information_schema.KEY_COLUMN_USAGE "
        "WHERE CONSTRAINT_NAME = 'PRIMARY' "
        "  AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')";

    auto pk_result = conn->execute(PK_QUERY);
    if (pk_result.success && pk_result.has_rows) {
        for (const auto& row : pk_result.rows) {
            if (row.size() < 3) continue;

            std::string pk_schema = utils::to_lower(row[0]);
            std::string pk_table  = utils::to_lower(row[1]);
            std::string pk_col    = utils::to_lower(row[2]);

            std::string pk_key;
            pk_key.reserve(pk_schema.size() + 1 + pk_table.size());
            pk_key = pk_schema;
            pk_key += '.';
            pk_key += pk_table;

            auto it = cache->find(pk_key);
            if (it == cache->end()) continue;

            auto& table = it->second;
            auto col_it = table->column_index.find(pk_col);
            if (col_it != table->column_index.end() && col_it->second < table->columns.size()) {
                table->columns[col_it->second].is_primary_key = true;
            }
        }
    }

    return cache;
}

} // namespace sqlproxy
