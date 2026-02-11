#pragma once

#include "core/types.hpp"
#include <string>
#include <unordered_map>
#include <vector>

namespace sqlproxy {

class SyntheticDataGenerator {
public:
    struct Config {
        bool enabled = false;
        size_t max_rows = 10000;
    };

    struct GeneratedData {
        std::vector<std::string> column_names;
        std::vector<std::vector<std::string>> rows;
    };

    SyntheticDataGenerator();
    explicit SyntheticDataGenerator(Config config);

    [[nodiscard]] bool is_enabled() const { return config_.enabled; }

    [[nodiscard]] GeneratedData generate(
        const TableMetadata& table,
        const std::unordered_map<std::string, ClassificationType>& classifications,
        size_t count) const;

private:
    [[nodiscard]] std::string generate_value(
        const ColumnMetadata& col, ClassificationType ct, size_t idx) const;

    Config config_;
};

} // namespace sqlproxy
