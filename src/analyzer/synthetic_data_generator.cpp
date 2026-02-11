#include "analyzer/synthetic_data_generator.hpp"

#include <algorithm>
#include <format>

namespace sqlproxy {

SyntheticDataGenerator::SyntheticDataGenerator() : SyntheticDataGenerator(Config{}) {}

SyntheticDataGenerator::SyntheticDataGenerator(Config config)
    : config_(std::move(config)) {}

SyntheticDataGenerator::GeneratedData SyntheticDataGenerator::generate(
    const TableMetadata& table,
    const std::unordered_map<std::string, ClassificationType>& classifications,
    size_t count) const {

    GeneratedData result;
    count = std::min(count, config_.max_rows);

    result.column_names.reserve(table.columns.size());
    for (const auto& col : table.columns) {
        result.column_names.push_back(col.name);
    }

    result.rows.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        std::vector<std::string> row;
        row.reserve(table.columns.size());

        for (const auto& col : table.columns) {
            ClassificationType ct = ClassificationType::NONE;
            const auto it = classifications.find(col.name);
            if (it != classifications.end()) {
                ct = it->second;
            }
            row.push_back(generate_value(col, ct, i));
        }

        result.rows.emplace_back(std::move(row));
    }

    return result;
}

std::string SyntheticDataGenerator::generate_value(
    const ColumnMetadata& col, ClassificationType ct, size_t idx) const {

    // PII-aware generators
    switch (ct) {
        case ClassificationType::PII_EMAIL:
            return std::format("user{}@example.com", idx + 1);
        case ClassificationType::PII_PHONE:
            return std::format("555-{:04d}", static_cast<int>((idx + 100) % 10000));
        case ClassificationType::PII_SSN:
            return std::format("000-00-{:04d}", static_cast<int>((idx + 1) % 10000));
        case ClassificationType::PII_CREDIT_CARD:
            return std::format("4111111111{:06d}", static_cast<int>((idx) % 1000000));
        case ClassificationType::SENSITIVE_SALARY:
            return std::to_string(30000 + ((idx * 1000) % 170000));
        case ClassificationType::SENSITIVE_PASSWORD:
            return std::format("$2b$12$synthetic_hash_{:06d}", idx);
        default:
            break;
    }

    // Type-based generators (fall through from NONE/CUSTOM)
    const auto& type = col.type;

    // Integer types
    if (type == "integer" || type == "int4" || type == "int" || type == "serial") {
        return std::to_string(idx + 1);
    }
    if (type == "bigint" || type == "int8" || type == "bigserial") {
        return std::to_string(idx + 1);
    }
    if (type == "smallint" || type == "int2") {
        return std::to_string((idx % 32000) + 1);
    }

    // Boolean
    if (type == "boolean" || type == "bool") {
        return (idx % 2 == 0) ? "true" : "false";
    }

    // Numeric/decimal
    if (type == "numeric" || type == "decimal" || type == "float8" ||
        type == "double precision" || type == "real" || type == "float4") {
        return std::format("{:.2f}", static_cast<double>(idx) * 1.5 + 0.5);
    }

    // Timestamp
    if (type.find("timestamp") != std::string::npos || type == "date") {
        // Generate dates from 2024-01-01 onwards
        const int day = static_cast<int>((idx % 28) + 1);
        const int month = static_cast<int>((idx / 28) % 12) + 1;
        return std::format("2024-{:02d}-{:02d}", month, day);
    }

    // UUID
    if (type == "uuid") {
        return std::format("00000000-0000-0000-0000-{:012d}", idx);
    }

    // JSON/JSONB
    if (type == "json" || type == "jsonb") {
        return std::format("{{\"key\": \"value_{}\"}}", idx);
    }

    // Default: text/varchar
    return std::format("{}_{}", col.name, idx + 1);
}

} // namespace sqlproxy
