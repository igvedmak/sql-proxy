#include "db/mysql/mysql_type_map.hpp"
#include <algorithm>
#include <unordered_map>

namespace sqlproxy {

GenericColumnType MysqlTypeMap::field_type_to_generic(enum_field_types field_type) {
    switch (field_type) {
        case MYSQL_TYPE_TINY:
        case MYSQL_TYPE_SHORT:
            return GenericColumnType::SMALLINT;
        case MYSQL_TYPE_LONG:
        case MYSQL_TYPE_INT24:
            return GenericColumnType::INTEGER;
        case MYSQL_TYPE_LONGLONG:
            return GenericColumnType::BIGINT;
        case MYSQL_TYPE_FLOAT:
            return GenericColumnType::REAL;
        case MYSQL_TYPE_DOUBLE:
            return GenericColumnType::DOUBLE_PRECISION;
        case MYSQL_TYPE_DECIMAL:
        case MYSQL_TYPE_NEWDECIMAL:
            return GenericColumnType::NUMERIC;
        case MYSQL_TYPE_STRING:
            return GenericColumnType::CHAR;
        case MYSQL_TYPE_VAR_STRING:
        case MYSQL_TYPE_VARCHAR:
            return GenericColumnType::VARCHAR;
        case MYSQL_TYPE_BLOB:
        case MYSQL_TYPE_TINY_BLOB:
        case MYSQL_TYPE_MEDIUM_BLOB:
        case MYSQL_TYPE_LONG_BLOB:
            return GenericColumnType::BLOB;
        case MYSQL_TYPE_DATE:
        case MYSQL_TYPE_NEWDATE:
            return GenericColumnType::DATE;
        case MYSQL_TYPE_TIME:
        case MYSQL_TYPE_TIME2:
            return GenericColumnType::TIME;
        case MYSQL_TYPE_DATETIME:
        case MYSQL_TYPE_DATETIME2:
        case MYSQL_TYPE_TIMESTAMP:
        case MYSQL_TYPE_TIMESTAMP2:
            return GenericColumnType::TIMESTAMP;
        case MYSQL_TYPE_JSON:
            return GenericColumnType::JSON;
        case MYSQL_TYPE_YEAR:
            return GenericColumnType::INTEGER;
        case MYSQL_TYPE_BIT:
            return GenericColumnType::VENDOR_SPECIFIC;
        case MYSQL_TYPE_ENUM:
        case MYSQL_TYPE_SET:
            return GenericColumnType::VARCHAR;
        case MYSQL_TYPE_GEOMETRY:
            return GenericColumnType::VENDOR_SPECIFIC;
        default:
            return GenericColumnType::UNKNOWN;
    }
}

ColumnTypeInfo MysqlTypeMap::build_type_info(
    enum_field_types field_type, const char* field_name) {

    ColumnTypeInfo info;
    info.vendor_type_id = static_cast<uint32_t>(field_type);
    info.vendor_type_name = field_name ? field_name : "";
    info.generic_type = field_type_to_generic(field_type);
    return info;
}

GenericColumnType MysqlTypeMap::type_name_to_generic(const std::string& type_name) {
    std::string lower = type_name;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    static const std::unordered_map<std::string, GenericColumnType> TYPE_MAP = {
        {"tinyint", GenericColumnType::SMALLINT},
        {"smallint", GenericColumnType::SMALLINT},
        {"mediumint", GenericColumnType::INTEGER},
        {"int", GenericColumnType::INTEGER},
        {"integer", GenericColumnType::INTEGER},
        {"bigint", GenericColumnType::BIGINT},
        {"float", GenericColumnType::REAL},
        {"double", GenericColumnType::DOUBLE_PRECISION},
        {"decimal", GenericColumnType::NUMERIC},
        {"numeric", GenericColumnType::NUMERIC},
        {"char", GenericColumnType::CHAR},
        {"varchar", GenericColumnType::VARCHAR},
        {"text", GenericColumnType::TEXT},
        {"tinytext", GenericColumnType::TEXT},
        {"mediumtext", GenericColumnType::TEXT},
        {"longtext", GenericColumnType::TEXT},
        {"blob", GenericColumnType::BLOB},
        {"tinyblob", GenericColumnType::BLOB},
        {"mediumblob", GenericColumnType::BLOB},
        {"longblob", GenericColumnType::BLOB},
        {"binary", GenericColumnType::BLOB},
        {"varbinary", GenericColumnType::BLOB},
        {"date", GenericColumnType::DATE},
        {"time", GenericColumnType::TIME},
        {"datetime", GenericColumnType::TIMESTAMP},
        {"timestamp", GenericColumnType::TIMESTAMP},
        {"year", GenericColumnType::INTEGER},
        {"boolean", GenericColumnType::BOOLEAN},
        {"bool", GenericColumnType::BOOLEAN},
        {"json", GenericColumnType::JSON},
        {"enum", GenericColumnType::VARCHAR},
        {"set", GenericColumnType::VARCHAR},
        {"bit", GenericColumnType::VENDOR_SPECIFIC},
        {"geometry", GenericColumnType::VENDOR_SPECIFIC},
    };

    auto it = TYPE_MAP.find(lower);
    return it != TYPE_MAP.end() ? it->second : GenericColumnType::UNKNOWN;
}

} // namespace sqlproxy
