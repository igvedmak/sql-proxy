#include "tenant/tenant_manager.hpp"

namespace sqlproxy {

TenantManager::TenantManager(const TenantConfig& config)
    : config_(config),
      tenants_(std::make_shared<const std::unordered_map<std::string, std::shared_ptr<TenantContext>>>()) {}

std::shared_ptr<TenantContext> TenantManager::resolve(const std::string& tenant_id) const {
    // RCU read: grab snapshot under shared lock
    std::shared_ptr<const std::unordered_map<std::string, std::shared_ptr<TenantContext>>> snapshot;
    {
        std::shared_lock lock(mutex_);
        snapshot = tenants_;
    }

    // Lookup without holding lock
    const auto& id = tenant_id.empty() ? config_.default_tenant : tenant_id;
    auto it = snapshot->find(id);
    if (it != snapshot->end()) {
        return it->second;
    }

    // Fallback to default tenant
    if (!tenant_id.empty() && tenant_id != config_.default_tenant) {
        it = snapshot->find(config_.default_tenant);
        if (it != snapshot->end()) {
            return it->second;
        }
    }

    return nullptr;
}

void TenantManager::register_tenant(std::string id, std::shared_ptr<TenantContext> ctx) {
    std::unique_lock lock(mutex_);
    // Copy-on-write: make mutable copy, insert, swap
    auto new_map = std::make_shared<std::unordered_map<std::string, std::shared_ptr<TenantContext>>>(*tenants_);
    (*new_map)[std::move(id)] = std::move(ctx);
    tenants_ = std::move(new_map);
}

void TenantManager::reload_tenants(
    std::unordered_map<std::string, std::shared_ptr<TenantContext>> tenants) {
    std::unique_lock lock(mutex_);
    tenants_ = std::make_shared<const std::unordered_map<std::string, std::shared_ptr<TenantContext>>>(
        std::move(tenants));
}

size_t TenantManager::tenant_count() const {
    std::shared_lock lock(mutex_);
    return tenants_->size();
}

} // namespace sqlproxy
