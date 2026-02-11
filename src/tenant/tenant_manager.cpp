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

bool TenantManager::remove_tenant(const std::string& id) {
    std::unique_lock lock(mutex_);
    auto new_map = std::make_shared<std::unordered_map<std::string, std::shared_ptr<TenantContext>>>(*tenants_);
    const bool erased = new_map->erase(id) > 0;
    if (erased) {
        tenants_ = std::move(new_map);
    }
    return erased;
}

std::vector<std::string> TenantManager::list_tenants() const {
    std::shared_ptr<const std::unordered_map<std::string, std::shared_ptr<TenantContext>>> snapshot;
    {
        std::shared_lock lock(mutex_);
        snapshot = tenants_;
    }
    std::vector<std::string> result;
    result.reserve(snapshot->size());
    for (const auto& [id, _] : *snapshot) {
        result.push_back(id);
    }
    return result;
}

std::shared_ptr<TenantContext> TenantManager::get_tenant(const std::string& id) const {
    std::shared_ptr<const std::unordered_map<std::string, std::shared_ptr<TenantContext>>> snapshot;
    {
        std::shared_lock lock(mutex_);
        snapshot = tenants_;
    }
    auto it = snapshot->find(id);
    return (it != snapshot->end()) ? it->second : nullptr;
}

} // namespace sqlproxy
