#include "db/postgresql/pg_type_map.hpp"
#include <unordered_map>

namespace sqlproxy {

uint32_t PgTypeMap::type_name_to_oid(const std::string& type_name) {
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

    auto it = TYPE_OIDS.find(type_name);
    return it != TYPE_OIDS.end() ? it->second : 0;
}

GenericColumnType PgTypeMap::oid_to_generic_type(uint32_t oid) {
    static const std::unordered_map<uint32_t, GenericColumnType> OID_TO_GENERIC = {
        {21, GenericColumnType::SMALLINT},
        {23, GenericColumnType::INTEGER},
        {20, GenericColumnType::BIGINT},
        {700, GenericColumnType::REAL},
        {701, GenericColumnType::DOUBLE_PRECISION},
        {1700, GenericColumnType::NUMERIC},
        {25, GenericColumnType::TEXT},
        {1043, GenericColumnType::VARCHAR},
        {1042, GenericColumnType::CHAR},
        {16, GenericColumnType::BOOLEAN},
        {1082, GenericColumnType::DATE},
        {1083, GenericColumnType::TIME},
        {1266, GenericColumnType::TIME},
        {1114, GenericColumnType::TIMESTAMP},
        {1184, GenericColumnType::TIMESTAMP_TZ},
        {1186, GenericColumnType::INTERVAL},
        {17, GenericColumnType::BLOB},
        {114, GenericColumnType::JSON},
        {3802, GenericColumnType::JSONB},
        {2950, GenericColumnType::UUID},
        {869, GenericColumnType::INET},
        {650, GenericColumnType::INET},
        {829, GenericColumnType::VENDOR_SPECIFIC},  // macaddr
        {790, GenericColumnType::MONEY},
        {142, GenericColumnType::XML},
        {26, GenericColumnType::INTEGER},  // oid
        {600, GenericColumnType::VENDOR_SPECIFIC},  // point
        {628, GenericColumnType::VENDOR_SPECIFIC},  // line
        {601, GenericColumnType::VENDOR_SPECIFIC},  // lseg
        {603, GenericColumnType::VENDOR_SPECIFIC},  // box
        {602, GenericColumnType::VENDOR_SPECIFIC},  // path
        {604, GenericColumnType::VENDOR_SPECIFIC},  // polygon
        {718, GenericColumnType::VENDOR_SPECIFIC},  // circle
        {3614, GenericColumnType::VENDOR_SPECIFIC}, // tsvector
        {3615, GenericColumnType::VENDOR_SPECIFIC}, // tsquery
        {2277, GenericColumnType::ARRAY},
    };

    auto it = OID_TO_GENERIC.find(oid);
    return it != OID_TO_GENERIC.end() ? it->second : GenericColumnType::UNKNOWN;
}

GenericColumnType PgTypeMap::type_name_to_generic(const std::string& type_name) {
    uint32_t oid = type_name_to_oid(type_name);
    if (oid == 0) {
        return GenericColumnType::UNKNOWN;
    }
    return oid_to_generic_type(oid);
}

ColumnTypeInfo PgTypeMap::build_type_info(const std::string& type_name) {
    ColumnTypeInfo info;
    info.vendor_type_id = type_name_to_oid(type_name);
    info.vendor_type_name = type_name;
    info.generic_type = oid_to_generic_type(info.vendor_type_id);
    return info;
}

} // namespace sqlproxy
