#include "db/postgresql/pg_backend.hpp"
#include "db/postgresql/pg_connection.hpp"
#include "db/postgresql/pg_sql_parser.hpp"
#include "db/postgresql/pg_schema_loader.hpp"
#include "db/generic_connection_pool.hpp"
#include "db/backend_registry.hpp"

namespace sqlproxy {

std::shared_ptr<IConnectionPool> PgBackend::create_pool(
    const std::string& db_name,
    const PoolConfig& config,
    std::shared_ptr<CircuitBreaker> circuit_breaker) {

    auto factory = std::make_shared<PgConnectionFactory>();
    return std::make_shared<GenericConnectionPool>(
        db_name, config, std::move(factory), std::move(circuit_breaker));
}

std::shared_ptr<ISqlParser> PgBackend::create_parser(
    std::shared_ptr<ParseCache> cache) {

    return std::make_shared<PgSqlParser>(std::move(cache));
}

std::shared_ptr<ISchemaLoader> PgBackend::create_schema_loader() {
    return std::make_shared<PgSchemaLoader>();
}

// Auto-register PostgreSQL backend at static initialization
namespace {
    struct PgBackendRegistrar {
        PgBackendRegistrar() {
            BackendRegistry::instance().register_backend(
                DatabaseType::POSTGRESQL,
                [] { return std::make_unique<PgBackend>(); });
        }
    };
    static PgBackendRegistrar pg_registrar;
}

} // namespace sqlproxy
