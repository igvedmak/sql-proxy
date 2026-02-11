#pragma once

#include <functional>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace sqlproxy {

class IConnectionPool;

class TenantPoolRegistry {
public:
    struct Config {
        size_t default_max_connections = 10;
        size_t default_min_connections = 2;
    };

    using PoolFactory = std::function<std::shared_ptr<IConnectionPool>(
        const std::string& tenant_id, const std::string& database, size_t max_conn)>;

    TenantPoolRegistry();
    explicit TenantPoolRegistry(Config config);

    void set_pool_factory(PoolFactory factory);

    [[nodiscard]] std::shared_ptr<IConnectionPool> get_pool(
        const std::string& tenant_id, const std::string& database);

    void set_tenant_config(const std::string& tenant, const std::string& database, size_t max_conn);

    struct Stats {
        size_t total_pools;
        size_t total_tenants;
    };
    [[nodiscard]] Stats get_stats() const;

private:
    Config config_;
    PoolFactory factory_;
    std::unordered_map<std::string, std::shared_ptr<IConnectionPool>> pools_; // key: "tenant:db"
    std::unordered_map<std::string, size_t> tenant_max_connections_; // key: "tenant:db" -> max_conn
    mutable std::shared_mutex mutex_;
};

} // namespace sqlproxy
