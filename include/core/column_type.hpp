#pragma once

#include <cstdint>
#include <string>

namespace sqlproxy {

/**
 * @brief Database-agnostic column type classification
 *
 * Maps from vendor-specific types (PG OIDs, MySQL field types).
 * Used for PII classification and result metadata.
 */
enum class GenericColumnType : uint16_t {
    UNKNOWN = 0,

    // Integer family
    SMALLINT,
    INTEGER,
    BIGINT,

    // Floating point
    REAL,
    DOUBLE_PRECISION,
    NUMERIC,

    // String family
    TEXT,
    VARCHAR,
    CHAR,

    // Boolean
    BOOLEAN,

    // Date/Time
    DATE,
    TIME,
    TIMESTAMP,
    TIMESTAMP_TZ,
    INTERVAL,

    // Binary
    BLOB,

    // JSON
    JSON,
    JSONB,

    // UUID
    UUID,

    // Network
    INET,
    MACADDR,

    // Monetary
    MONEY,

    // XML
    XML,

    // Array
    ARRAY,

    // Vendor-specific fallback
    VENDOR_SPECIFIC,
};

/**
 * @brief Extended column type info carrying both generic and vendor-specific data
 */
struct ColumnTypeInfo {
    GenericColumnType generic_type = GenericColumnType::UNKNOWN;
    uint32_t vendor_type_id = 0;       // PG OID or MySQL field type enum
    std::string vendor_type_name;      // "integer", "INT", etc.

    ColumnTypeInfo() = default;
    ColumnTypeInfo(GenericColumnType gt, uint32_t vid, std::string vname)
        : generic_type(gt), vendor_type_id(vid), vendor_type_name(std::move(vname)) {}
};

[[nodiscard]] inline const char* generic_column_type_to_string(GenericColumnType type) {
    switch (type) {
        case GenericColumnType::UNKNOWN: return "UNKNOWN";
        case GenericColumnType::SMALLINT: return "SMALLINT";
        case GenericColumnType::INTEGER: return "INTEGER";
        case GenericColumnType::BIGINT: return "BIGINT";
        case GenericColumnType::REAL: return "REAL";
        case GenericColumnType::DOUBLE_PRECISION: return "DOUBLE_PRECISION";
        case GenericColumnType::NUMERIC: return "NUMERIC";
        case GenericColumnType::TEXT: return "TEXT";
        case GenericColumnType::VARCHAR: return "VARCHAR";
        case GenericColumnType::CHAR: return "CHAR";
        case GenericColumnType::BOOLEAN: return "BOOLEAN";
        case GenericColumnType::DATE: return "DATE";
        case GenericColumnType::TIME: return "TIME";
        case GenericColumnType::TIMESTAMP: return "TIMESTAMP";
        case GenericColumnType::TIMESTAMP_TZ: return "TIMESTAMP_TZ";
        case GenericColumnType::INTERVAL: return "INTERVAL";
        case GenericColumnType::BLOB: return "BLOB";
        case GenericColumnType::JSON: return "JSON";
        case GenericColumnType::JSONB: return "JSONB";
        case GenericColumnType::UUID: return "UUID";
        case GenericColumnType::INET: return "INET";
        case GenericColumnType::MACADDR: return "MACADDR";
        case GenericColumnType::MONEY: return "MONEY";
        case GenericColumnType::XML: return "XML";
        case GenericColumnType::ARRAY: return "ARRAY";
        case GenericColumnType::VENDOR_SPECIFIC: return "VENDOR_SPECIFIC";
        default: return "UNKNOWN";
    }
}

} // namespace sqlproxy
