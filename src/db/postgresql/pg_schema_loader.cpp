#include "db/postgresql/pg_schema_loader.hpp"
#include "db/postgresql/pg_type_map.hpp"
#include "db/schema_constants.hpp"
#include "core/utils.hpp"
#include <libpq-fe.h>
#include <memory>
#include <string>

namespace sqlproxy {

static constexpr char kDot = '.';

// RAII wrappers for libpq resources
struct PGConnDeleter {
    void operator()(PGconn* conn) const noexcept {
        if (conn) {
            PQfinish(conn);
        }
    }
};
using PGConnPtr = std::unique_ptr<PGconn, PGConnDeleter>;

struct PGResultDeleter {
    void operator()(PGresult* res) const noexcept {
        if (res) {
            PQclear(res);
        }
    }
};
using PGResultPtr = std::unique_ptr<PGresult, PGResultDeleter>;

std::shared_ptr<SchemaMap> PgSchemaLoader::load_schema(const std::string& conn_string) {
    auto cache = std::make_shared<SchemaMap>();

    // Connect to PostgreSQL
    PGConnPtr conn(PQconnectdb(conn_string.c_str()));
    if (!conn || PQstatus(conn.get()) != CONNECTION_OK) {
        return cache;
    }

    // Query information_schema for all user-defined table columns
    static constexpr const char* SCHEMA_QUERY =
        "SELECT "
        "    table_schema, "
        "    table_name, "
        "    column_name, "
        "    data_type, "
        "    is_nullable, "
        "    column_default, "
        "    ordinal_position "
        "FROM information_schema.columns "
        "WHERE table_schema NOT IN ('pg_catalog', 'information_schema') "
        "ORDER BY table_schema, table_name, ordinal_position;";

    PGResultPtr res(PQexec(conn.get(), SCHEMA_QUERY));
    if (!res || PQresultStatus(res.get()) != PGRES_TUPLES_OK) {
        return cache;
    }

    const int nrows = PQntuples(res.get());

    // Column indices in the result set (matching the SELECT order)
    static constexpr int COL_SCHEMA      = 0;
    static constexpr int COL_TABLE       = 1;
    static constexpr int COL_COLUMN      = 2;
    static constexpr int COL_DATA_TYPE   = 3;
    static constexpr int COL_IS_NULLABLE = 4;

    // Track the current table being built so we can accumulate columns
    // without repeated map lookups. The query is ordered by (schema, table, ordinal)
    // so all columns for a given table arrive consecutively.
    std::string current_key;
    std::shared_ptr<TableMetadata> current_table;

    for (int row = 0; row < nrows; ++row) {
        const char* schema_raw   = PQgetvalue(res.get(), row, COL_SCHEMA);
        const char* table_raw    = PQgetvalue(res.get(), row, COL_TABLE);
        const char* column_raw   = PQgetvalue(res.get(), row, COL_COLUMN);
        const char* type_raw     = PQgetvalue(res.get(), row, COL_DATA_TYPE);
        const char* nullable_raw = PQgetvalue(res.get(), row, COL_IS_NULLABLE);

        // Build the qualified key: "schema.table" (lowercased)
        std::string schema_name = utils::to_lower(schema_raw ? schema_raw : "public");
        std::string table_name  = utils::to_lower(table_raw  ? table_raw  : "");
        std::string column_name = utils::to_lower(column_raw ? column_raw : "");
        std::string data_type   = utils::to_lower(type_raw   ? type_raw   : "");
        std::string nullable_str = nullable_raw ? nullable_raw : std::string(db::kYes);

        // Construct the map key
        std::string key;
        key.reserve(schema_name.size() + 1 + table_name.size());
        key = schema_name;
        key += kDot;
        key += table_name;

        // If we've moved to a new table, finalize the previous one and start fresh
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

        // Build ColumnMetadata for this row
        uint32_t type_oid = PgTypeMap::type_name_to_oid(data_type);
        bool is_nullable = (nullable_str == db::kYes || nullable_str == db::kYesLow);
        ColumnMetadata col(std::move(column_name), std::move(data_type), type_oid, is_nullable, false);

        // Record the column index for fast name-based lookup
        const size_t col_index = current_table->columns.size();
        current_table->column_index[col.name] = col_index;
        current_table->columns.push_back(std::move(col));
    }

    // Don't forget the last table
    if (current_table && !current_key.empty()) {
        (*cache)[current_key] = std::move(current_table);
    }

    // Second pass: load primary key information from pg_catalog
    static constexpr const char* PK_QUERY =
        "SELECT "
        "    n.nspname AS table_schema, "
        "    c.relname AS table_name, "
        "    a.attname AS column_name "
        "FROM pg_index i "
        "JOIN pg_class c ON c.oid = i.indrelid "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey) "
        "WHERE i.indisprimary "
        "  AND n.nspname NOT IN ('pg_catalog', 'information_schema');";

    PGResultPtr pk_res(PQexec(conn.get(), PK_QUERY));
    if (pk_res && PQresultStatus(pk_res.get()) == PGRES_TUPLES_OK) {
        const int pk_rows = PQntuples(pk_res.get());

        for (int row = 0; row < pk_rows; ++row) {
            const char* pk_schema_raw = PQgetvalue(pk_res.get(), row, 0);
            const char* pk_table_raw  = PQgetvalue(pk_res.get(), row, 1);
            const char* pk_col_raw    = PQgetvalue(pk_res.get(), row, 2);

            std::string pk_schema = utils::to_lower(pk_schema_raw ? pk_schema_raw : "");
            std::string pk_table  = utils::to_lower(pk_table_raw  ? pk_table_raw  : "");
            std::string pk_col    = utils::to_lower(pk_col_raw    ? pk_col_raw    : "");

            // Build the lookup key
            std::string pk_key;
            pk_key.reserve(pk_schema.size() + 1 + pk_table.size());
            pk_key = pk_schema;
            pk_key += kDot;
            pk_key += pk_table;

            const auto it = cache->find(pk_key);
            if (it == cache->end()) {
                continue;
            }

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
