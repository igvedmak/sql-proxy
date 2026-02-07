#include "db/mysql/mysql_backend.hpp"
#include "db/mysql/mysql_connection.hpp"
#include "db/mysql/mysql_sql_parser.hpp"
#include "db/mysql/mysql_schema_loader.hpp"
#include "db/generic_connection_pool.hpp"
#include "db/backend_registry.hpp"

namespace sqlproxy {

std::shared_ptr<IConnectionPool> MysqlBackend::create_pool(
    const std::string& db_name,
    const PoolConfig& config,
    std::shared_ptr<CircuitBreaker> circuit_breaker) {

    auto factory = std::make_shared<MysqlConnectionFactory>();
    return std::make_shared<GenericConnectionPool>(
        db_name, config, std::move(factory), std::move(circuit_breaker));
}

std::shared_ptr<ISqlParser> MysqlBackend::create_parser(
    std::shared_ptr<ParseCache> cache) {

    return std::make_shared<MysqlSqlParser>(std::move(cache));
}

std::shared_ptr<ISchemaLoader> MysqlBackend::create_schema_loader() {
    return std::make_shared<MysqlSchemaLoader>();
}

// Auto-register MySQL backend at static initialization
namespace {
    struct MysqlBackendRegistrar {
        MysqlBackendRegistrar() {
            BackendRegistry::instance().register_backend(
                DatabaseType::MYSQL,
                [] { return std::make_unique<MysqlBackend>(); });
        }
    };
    static MysqlBackendRegistrar mysql_registrar;
}

} // namespace sqlproxy
