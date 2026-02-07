#pragma once

#include "core/database_type.hpp"
#include "db/iconnection_pool.hpp"
#include "db/isql_parser.hpp"
#include "db/ischema_loader.hpp"
#include "executor/circuit_breaker.hpp"
#include "parser/parse_cache.hpp"
#include <memory>
#include <string>

namespace sqlproxy {

/**
 * @brief Abstract database backend — creates all DB-specific components
 *
 * Each database type (PostgreSQL, MySQL) provides a concrete implementation
 * that creates the right parser, pool, schema loader, etc.
 *
 * Usage:
 *   auto backend = BackendRegistry::instance().create(DatabaseType::POSTGRESQL);
 *   auto pool = backend->create_pool("testdb", config, circuit_breaker);
 *   auto parser = backend->create_parser(parse_cache);
 */
class IDbBackend {
public:
    virtual ~IDbBackend() = default;

    /** @brief Database type this backend supports */
    [[nodiscard]] virtual DatabaseType type() const = 0;

    /** @brief Create a connection pool */
    [[nodiscard]] virtual std::shared_ptr<IConnectionPool> create_pool(
        const std::string& db_name,
        const PoolConfig& config,
        std::shared_ptr<CircuitBreaker> circuit_breaker = nullptr) = 0;

    /** @brief Create the SQL parser for this dialect */
    [[nodiscard]] virtual std::shared_ptr<ISqlParser> create_parser(
        std::shared_ptr<ParseCache> cache = nullptr) = 0;

    /** @brief Create the schema loader for this dialect */
    [[nodiscard]] virtual std::shared_ptr<ISchemaLoader> create_schema_loader() = 0;
};

} // namespace sqlproxy
