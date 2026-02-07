#pragma once

#include "db/idb_backend.hpp"

namespace sqlproxy {

/**
 * @brief PostgreSQL backend — creates all PG-specific components
 *
 * Creates:
 * - PgConnectionFactory → GenericConnectionPool
 * - PgSqlParser (wraps libpg_query)
 * - PgSchemaLoader (queries information_schema + pg_catalog)
 *
 * Auto-registers with BackendRegistry at static init time.
 */
class PgBackend : public IDbBackend {
public:
    [[nodiscard]] DatabaseType type() const override {
        return DatabaseType::POSTGRESQL;
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
