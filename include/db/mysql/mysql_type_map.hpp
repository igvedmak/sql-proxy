#pragma once

#include "core/column_type.hpp"
#include <mysql/mysql.h>
#include <cstdint>
#include <string>

namespace sqlproxy {

/**
 * @brief MySQL type mapping utilities
 *
 * Maps between MySQL field types and GenericColumnType.
 */
class MysqlTypeMap {
public:
    /**
     * @brief Map MySQL field type to GenericColumnType
     * @param field_type MySQL enum_field_types value
     * @return Generic column type
     */
    [[nodiscard]] static GenericColumnType field_type_to_generic(enum_field_types field_type);

    /**
     * @brief Build a full ColumnTypeInfo from MySQL field type
     * @param field_type MySQL enum_field_types value
     * @param field_name Field name for vendor_type_name
     * @return Complete type info
     */
    [[nodiscard]] static ColumnTypeInfo build_type_info(
        enum_field_types field_type, const char* field_name);

    /**
     * @brief Map MySQL type name to GenericColumnType
     * @param type_name MySQL type name (e.g., "INT", "VARCHAR")
     * @return Generic column type
     */
    [[nodiscard]] static GenericColumnType type_name_to_generic(const std::string& type_name);
};

} // namespace sqlproxy
