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
    enum class TypeCategory { INTEGER, BIGINT, SMALLINT, BOOLEAN, NUMERIC, DATE, UUID, JSON, TEXT };

    static const std::unordered_map<std::string, TypeCategory> kTypeMap = {
        {"integer",          TypeCategory::INTEGER},
        {"int4",             TypeCategory::INTEGER},
        {"int",              TypeCategory::INTEGER},
        {"serial",           TypeCategory::INTEGER},
        {"bigint",           TypeCategory::BIGINT},
        {"int8",             TypeCategory::BIGINT},
        {"bigserial",        TypeCategory::BIGINT},
        {"smallint",         TypeCategory::SMALLINT},
        {"int2",             TypeCategory::SMALLINT},
        {"boolean",          TypeCategory::BOOLEAN},
        {"bool",             TypeCategory::BOOLEAN},
        {"numeric",          TypeCategory::NUMERIC},
        {"decimal",          TypeCategory::NUMERIC},
        {"float8",           TypeCategory::NUMERIC},
        {"double precision", TypeCategory::NUMERIC},
        {"real",             TypeCategory::NUMERIC},
        {"float4",           TypeCategory::NUMERIC},
        {"date",             TypeCategory::DATE},
        {"uuid",             TypeCategory::UUID},
        {"json",             TypeCategory::JSON},
        {"jsonb",            TypeCategory::JSON},
    };

    const auto& type = col.type;
    auto it = kTypeMap.find(type);

    // Substring match for timestamp variants (e.g. "timestamp with time zone")
    if (it == kTypeMap.end() && type.find("timestamp") != std::string::npos) {
        it = kTypeMap.find("date");  // reuse DATE category
    }

    const auto category = (it != kTypeMap.end()) ? it->second : TypeCategory::TEXT;

    switch (category) {
        case TypeCategory::INTEGER:
            return std::format("{}", idx + 1);
        case TypeCategory::BIGINT:
            return std::format("{}", idx + 1);
        case TypeCategory::SMALLINT:
            return std::format("{}", (idx % 32000) + 1);
        case TypeCategory::BOOLEAN:
            return utils::booltostr(idx % 2 == 0);
        case TypeCategory::NUMERIC:
            return std::format("{:.2f}", static_cast<double>(idx) * 1.5 + 0.5);
        case TypeCategory::DATE: {
            const int day = static_cast<int>((idx % 28) + 1);
            const int month = static_cast<int>((idx / 28) % 12) + 1;
            return std::format("2024-{:02d}-{:02d}", month, day);
        }
        case TypeCategory::UUID:
            return std::format("00000000-0000-0000-0000-{:012d}", idx);
        case TypeCategory::JSON:
            return std::format("{{\"key\": \"value_{}\"}}", idx);
        case TypeCategory::TEXT:
            return std::format("{}_{}", col.name, idx + 1);
    }

    return std::format("{}_{}", col.name, idx + 1);
}

} // namespace sqlproxy
