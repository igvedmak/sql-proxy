#pragma once

#include "core/types.hpp"
#include <string>
#include <memory>

namespace sqlproxy {

/**
 * @brief Abstract schema loader interface
 *
 * Each backend queries its own catalog tables
 * (information_schema + pg_catalog for PG, information_schema for MySQL).
 */
class ISchemaLoader {
public:
    virtual ~ISchemaLoader() = default;

    /**
     * @brief Load full schema from the database
     * @param conn_string Connection string for the database
     * @return Populated SchemaMap, or nullptr on failure
     */
    [[nodiscard]] virtual std::shared_ptr<SchemaMap> load_schema(
        const std::string& conn_string) = 0;
};

} // namespace sqlproxy
