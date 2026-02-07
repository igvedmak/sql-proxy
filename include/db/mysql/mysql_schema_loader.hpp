#pragma once

#include "db/ischema_loader.hpp"

namespace sqlproxy {

/**
 * @brief MySQL schema loader
 *
 * Queries MySQL information_schema for table metadata.
 * Uses KEY_COLUMN_USAGE for primary key detection.
 */
class MysqlSchemaLoader : public ISchemaLoader {
public:
    ~MysqlSchemaLoader() override = default;

    [[nodiscard]] std::shared_ptr<SchemaMap> load_schema(
        const std::string& conn_string) override;
};

} // namespace sqlproxy
