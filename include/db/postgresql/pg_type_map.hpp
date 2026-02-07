#pragma once

#include "core/column_type.hpp"
#include <cstdint>
#include <string>

namespace sqlproxy {

/**
 * @brief PostgreSQL type mapping utilities
 *
 * Maps between PG type names, OIDs, and GenericColumnType.
 */
class PgTypeMap {
public:
    /**
     * @brief Map PostgreSQL type name to its OID
     * @param type_name Lowercase PostgreSQL type name
     * @return Type OID, or 0 if unknown
     */
    [[nodiscard]] static uint32_t type_name_to_oid(const std::string& type_name);

    /**
     * @brief Map PostgreSQL OID to GenericColumnType
     * @param oid PostgreSQL type OID
     * @return Generic column type
     */
    [[nodiscard]] static GenericColumnType oid_to_generic_type(uint32_t oid);

    /**
     * @brief Map PostgreSQL type name to GenericColumnType
     * @param type_name Lowercase PostgreSQL type name
     * @return Generic column type
     */
    [[nodiscard]] static GenericColumnType type_name_to_generic(const std::string& type_name);

    /**
     * @brief Build a full ColumnTypeInfo from PG type name
     * @param type_name Lowercase PostgreSQL type name
     * @return Complete type info with generic type, OID, and name
     */
    [[nodiscard]] static ColumnTypeInfo build_type_info(const std::string& type_name);
};

} // namespace sqlproxy
