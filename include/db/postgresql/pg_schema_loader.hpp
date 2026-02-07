#pragma once

#include "db/ischema_loader.hpp"

namespace sqlproxy {

/**
 * @brief PostgreSQL schema loader
 *
 * Queries information_schema.columns and pg_catalog for table metadata.
 * Extracted from SchemaCache::load_from_database() to allow
 * database-agnostic schema caching.
 */
class PgSchemaLoader : public ISchemaLoader {
public:
    ~PgSchemaLoader() override = default;

    /**
     * @brief Load schema from PostgreSQL database
     * @param conn_string PostgreSQL connection string
     * @return Populated SchemaMap, or empty map on failure
     */
    [[nodiscard]] std::shared_ptr<SchemaMap> load_schema(
        const std::string& conn_string) override;
};

} // namespace sqlproxy
