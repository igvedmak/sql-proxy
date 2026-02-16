#include "analyzer/schema_cache.hpp"
#include "db/schema_constants.hpp"
#include "policy/policy_constants.hpp"
#include "core/utils.hpp"
#include <libpq-fe.h>
#include <algorithm>
#include <cctype>
#include <memory>
#include <unordered_map>
#include <string>

namespace sqlproxy {

static constexpr char kDot = '.';

// ============================================================================
// PostgreSQL Type OID Mapping
// ============================================================================

/**
 * @brief Map common PostgreSQL type names to their OIDs
 *
 * Used during schema loading to populate ColumnMetadata::type_oid
 * from the text type names returned by information_schema.columns.
 *
 * @param type_name Lowercase PostgreSQL type name
 * @return Type OID, or 0 if unknown
 */
static uint32_t pg_type_oid(const std::string& type_name) {
    static const std::unordered_map<std::string, uint32_t> TYPE_OIDS = {
        {"integer", 23},    {"int4", 23},
        {"smallint", 21},   {"int2", 21},
        {"bigint", 20},     {"int8", 20},
        {"real", 700},      {"float4", 700},
        {"double precision", 701}, {"float8", 701},
        {"text", 25},
        {"varchar", 1043},  {"character varying", 1043},
        {"char", 1042},     {"character", 1042},
        {"boolean", 16},    {"bool", 16},
        {"date", 1082},
        {"time", 1083},     {"time without time zone", 1083},
        {"timetz", 1266},   {"time with time zone", 1266},
        {"timestamp", 1114},{"timestamp without time zone", 1114},
        {"timestamptz", 1184}, {"timestamp with time zone", 1184},
        {"numeric", 1700},  {"decimal", 1700},
        {"uuid", 2950},
        {"json", 114},      {"jsonb", 3802},
        {"bytea", 17},
        {"inet", 869},      {"cidr", 650},
        {"macaddr", 829},
        {"interval", 1186},
        {"serial", 23},     {"bigserial", 20},
        {"oid", 26},
        {"money", 790},
        {"xml", 142},
        {"point", 600},
        {"line", 628},
        {"lseg", 601},
        {"box", 603},
        {"path", 602},
        {"polygon", 604},
        {"circle", 718},
        {"tsvector", 3614}, {"tsquery", 3615},
        {"array", 2277},
        {"ARRAY", 2277},
        {"USER-DEFINED", 0},
    };

    const auto it = TYPE_OIDS.find(type_name);
    return it != TYPE_OIDS.end() ? it->second : 0;
}

// ============================================================================
// RAII Wrappers for libpq resources
// ============================================================================

/**
 * @brief RAII wrapper for PGconn* (auto-calls PQfinish on destruction)
 */
struct PGConnDeleter {
    void operator()(PGconn* conn) const noexcept {
        if (conn) {
            PQfinish(conn);
        }
    }
};
using PGConnPtr = std::unique_ptr<PGconn, PGConnDeleter>;

/**
 * @brief RAII wrapper for PGresult* (auto-calls PQclear on destruction)
 */
struct PGResultDeleter {
    void operator()(PGresult* res) const noexcept {
        if (res) {
            PQclear(res);
        }
    }
};
using PGResultPtr = std::unique_ptr<PGresult, PGResultDeleter>;

// ============================================================================
// Construction
// ============================================================================

SchemaCache::SchemaCache()
    : cache_ptr_(std::make_shared<::sqlproxy::SchemaMap>()),
      version_(0),
      loader_(nullptr) {}

SchemaCache::SchemaCache(const std::string& conn_string)
    : version_(0), loader_(nullptr) {

    const auto loaded_cache = load_from_database(conn_string);
    std::atomic_store_explicit(&cache_ptr_, loaded_cache, std::memory_order_release);
}

// ============================================================================
// Read Operations (wait-free via RCU)
// ============================================================================

std::shared_ptr<const TableMetadata> SchemaCache::get_table(const std::string& table_name) const {
    // RCU read: Load current cache pointer (wait-free atomic)
    const auto cache = std::atomic_load_explicit(&cache_ptr_, std::memory_order_acquire);

    if (!cache) {
        return nullptr;
    }

    const std::string normalized = normalize_table_name(table_name);

    const auto it = cache->find(normalized);
    if (it == cache->end()) {
        return nullptr;
    }

    return it->second;
}

bool SchemaCache::has_table(const std::string& table_name) const {
    return get_table(table_name) != nullptr;
}

SchemaMap SchemaCache::get_all_tables() const {
    const auto cache = std::atomic_load_explicit(&cache_ptr_, std::memory_order_acquire);
    if (!cache) {
        return {};
    }
    return *cache;
}

size_t SchemaCache::table_count() const {
    const auto cache = std::atomic_load_explicit(&cache_ptr_, std::memory_order_acquire);
    if (!cache) {
        return 0;
    }

    return cache->size();
}

// ============================================================================
// Write Operations (mutex-protected)
// ============================================================================

bool SchemaCache::reload(const std::string& conn_string) {
    std::lock_guard<std::mutex> lock(reload_mutex_);

    try {
        // Build new cache offline (outside the critical section would be ideal,
        // but the mutex ensures only one reload at a time regardless)
        std::shared_ptr<::sqlproxy::SchemaMap> new_cache;

        if (loader_) {
            // Use injected loader (for testing)
            auto loaded = loader_(conn_string);
            new_cache = std::make_shared<::sqlproxy::SchemaMap>(std::move(loaded));
        } else {
            new_cache = load_from_database(conn_string);
        }

        if (!new_cache) {
            return false;
        }

        // RCU write: Atomic pointer swap
        // In-flight readers still hold the old shared_ptr; it stays alive
        // until all readers release it. New readers pick up the new cache.
        std::atomic_store_explicit(&cache_ptr_, new_cache, std::memory_order_release);

        // Increment version so observers can detect schema changes
        version_.fetch_add(1, std::memory_order_release);

        return true;

    } catch (const std::exception& e) {
        utils::log::error(std::format("Schema cache reload failed (keeping existing cache): {}", e.what()));
        return false;
    }
}

void SchemaCache::clear() {
    std::lock_guard<std::mutex> lock(reload_mutex_);
    std::atomic_store_explicit(&cache_ptr_, std::make_shared<::sqlproxy::SchemaMap>(),
                               std::memory_order_release);
    version_.fetch_add(1, std::memory_order_release);
}

// ============================================================================
// Database Loading
// ============================================================================

std::shared_ptr<::sqlproxy::SchemaMap> SchemaCache::load_from_database(
    const std::string& conn_string) {

    auto cache = std::make_shared<::sqlproxy::SchemaMap>();

    // Connect to PostgreSQL
    PGConnPtr conn(PQconnectdb(conn_string.c_str()));
    if (!conn || PQstatus(conn.get()) != CONNECTION_OK) {
        // Connection failure - return empty cache rather than throwing.
        // Callers (constructor, reload) handle empty caches gracefully.
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
        // Query failure - return empty cache
        return cache;
    }

    const int nrows = PQntuples(res.get());

    // Column indices in the result set (matching the SELECT order)
    static constexpr int COL_SCHEMA      = 0;
    static constexpr int COL_TABLE       = 1;
    static constexpr int COL_COLUMN      = 2;
    static constexpr int COL_DATA_TYPE   = 3;
    static constexpr int COL_IS_NULLABLE = 4;
    // COL_DEFAULT = 5 (available but not stored in ColumnMetadata)
    // COL_ORDINAL = 6 (used for ordering, which the query handles)

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
        const std::string schema_name = utils::to_lower(schema_raw ? schema_raw : policy::kDefaultSchema.data());
        const std::string table_name  = utils::to_lower(table_raw  ? table_raw  : "");
        const std::string column_name = utils::to_lower(column_raw ? column_raw : "");
        const std::string data_type   = utils::to_lower(type_raw   ? type_raw   : "");
        const std::string nullable_str = nullable_raw ? nullable_raw : std::string(db::kYes);

        // Construct the map key
        std::string key;
        key.reserve(schema_name.size() + 1 + table_name.size());
        key = schema_name;
        key += kDot;
        key += table_name;

        // If we've moved to a new table, finalize the previous one and start fresh
        if (key != current_key) {
            // Save previous table if it exists
            if (current_table) {
                (*cache)[current_key] = std::move(current_table);
            }

            // Check if this table already exists in the cache (shouldn't happen
            // with ordered results, but defensive coding)
            const auto [it, inserted] = cache->try_emplace(key, nullptr);
            if (!inserted && it->second) {
                // Table already exists from a previous batch - continue building it
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
        const uint32_t type_oid = pg_type_oid(data_type);
        const bool is_nullable = (nullable_str == db::kYes || nullable_str == db::kYesLow);
        ColumnMetadata col(std::move(column_name), std::move(data_type), type_oid, is_nullable, false);

        // Record the column index for fast name-based lookup
        const size_t col_index = current_table->columns.size();
        current_table->column_index[col.name] = col_index;
        current_table->columns.emplace_back(std::move(col));
    }

    // Don't forget the last table
    if (current_table && !current_key.empty()) {
        (*cache)[current_key] = std::move(current_table);
    }

    // Second pass: load primary key information from pg_catalog
    // This enriches the ColumnMetadata::is_primary_key field
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

    const PGResultPtr pk_res(PQexec(conn.get(), PK_QUERY));
    if (pk_res && PQresultStatus(pk_res.get()) == PGRES_TUPLES_OK) {
        const int pk_rows = PQntuples(pk_res.get());

        for (int row = 0; row < pk_rows; ++row) {
            const char* pk_schema_raw = PQgetvalue(pk_res.get(), row, 0);
            const char* pk_table_raw  = PQgetvalue(pk_res.get(), row, 1);
            const char* pk_col_raw    = PQgetvalue(pk_res.get(), row, 2);

            const std::string pk_schema = utils::to_lower(pk_schema_raw ? pk_schema_raw : "");
            const std::string pk_table  = utils::to_lower(pk_table_raw  ? pk_table_raw  : "");
            const std::string pk_col    = utils::to_lower(pk_col_raw    ? pk_col_raw    : "");

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
            const auto col_it = table->column_index.find(pk_col);
            if (col_it != table->column_index.end() && col_it->second < table->columns.size()) {
                table->columns[col_it->second].is_primary_key = true;
            }
        }
    }
    // If PK query fails, we still have a usable cache - just without PK info

    return cache;
}

// ============================================================================
// String Normalization
// ============================================================================

std::string SchemaCache::normalize_table_name(const std::string& table_name) {
    // Check for dot before allocating to avoid double-allocation
    const bool needs_schema = !table_name.contains(kDot);

    std::string result;
    result.reserve(needs_schema ? 7 + table_name.size() : table_name.size());

    if (needs_schema) {
        result = "public.";
    }

    // Lowercase for case-insensitive matching
    for (const char c : table_name) {
        result += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    return result;
}

} // namespace sqlproxy
