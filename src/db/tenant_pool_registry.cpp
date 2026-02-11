#include "db/tenant_pool_registry.hpp"
#include "db/iconnection_pool.hpp"

#include <mutex>
#include <unordered_set>

namespace sqlproxy {

TenantPoolRegistry::TenantPoolRegistry() : TenantPoolRegistry(Config{}) {}

TenantPoolRegistry::TenantPoolRegistry(Config config)
    : config_(std::move(config)) {}

void TenantPoolRegistry::set_pool_factory(PoolFactory factory) {
    std::unique_lock lock(mutex_);
    factory_ = std::move(factory);
}

std::shared_ptr<IConnectionPool> TenantPoolRegistry::get_pool(
    const std::string& tenant_id, const std::string& database) {

    // Build composite key with optimized concatenation
    std::string key;
    key.reserve(tenant_id.size() + 1 + database.size());
    key = tenant_id;
    key += ':';
    key += database;

    // Fast path: shared lock (read-only)
    {
        std::shared_lock lock(mutex_);
        auto it = pools_.find(key);
        if (it != pools_.end()) {
            return it->second;
        }
        // No factory set — cannot create pools
        if (!factory_) {
            return nullptr;
        }
    }

    // Slow path: unique lock with double-checked locking
    std::unique_lock lock(mutex_);

    // Double-check: another thread may have created it
    auto [it, inserted] = pools_.try_emplace(key, nullptr);
    if (!inserted) {
        return it->second;
    }

    // Determine max connections for this tenant:db
    size_t max_conn = config_.default_max_connections;
    auto cfg_it = tenant_max_connections_.find(key);
    if (cfg_it != tenant_max_connections_.end()) {
        max_conn = cfg_it->second;
    }

    // Create pool via factory
    it->second = factory_(tenant_id, database, max_conn);
    return it->second;
}

void TenantPoolRegistry::set_tenant_config(
    const std::string& tenant, const std::string& database, size_t max_conn) {

    std::string key;
    key.reserve(tenant.size() + 1 + database.size());
    key = tenant;
    key += ':';
    key += database;

    std::unique_lock lock(mutex_);
    tenant_max_connections_[key] = max_conn;
}

TenantPoolRegistry::Stats TenantPoolRegistry::get_stats() const {
    std::shared_lock lock(mutex_);

    // Count unique tenants by extracting prefix before ':'
    std::unordered_set<std::string> tenants;
    for (const auto& [key, _] : pools_) {
        auto pos = key.find(':');
        if (pos != std::string::npos) {
            tenants.insert(key.substr(0, pos));
        }
    }

    return Stats{
        .total_pools = pools_.size(),
        .total_tenants = tenants.size(),
    };
}

} // namespace sqlproxy
