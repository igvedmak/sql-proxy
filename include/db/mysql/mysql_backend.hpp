#pragma once

#include "db/idb_backend.hpp"

namespace sqlproxy {

/**
 * @brief MySQL backend — creates all MySQL-specific components
 *
 * Creates:
 * - MysqlConnectionFactory → GenericConnectionPool
 * - MysqlSqlParser (regex-based MVP)
 * - MysqlSchemaLoader (information_schema + KEY_COLUMN_USAGE)
 *
 * Auto-registers with BackendRegistry at static init time.
 */
class MysqlBackend : public IDbBackend {
public:
    [[nodiscard]] DatabaseType type() const override {
        return DatabaseType::MYSQL;
    }

    [[nodiscard]] std::shared_ptr<IConnectionPool> create_pool(
        const std::string& db_name,
        const PoolConfig& config,
        std::shared_ptr<CircuitBreaker> circuit_breaker = nullptr) override;

    [[nodiscard]] std::shared_ptr<ISqlParser> create_parser(
        std::shared_ptr<ParseCache> cache = nullptr) override;

    [[nodiscard]] std::shared_ptr<ISchemaLoader> create_schema_loader() override;
};

} // namespace sqlproxy
