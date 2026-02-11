#pragma once

#include "tenant/tenant_context.hpp"
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace sqlproxy {

struct TenantConfig {
    bool enabled = false;
    std::string default_tenant = "default";
    std::string header_name = "X-Tenant-Id";
};

class TenantManager {
public:
    explicit TenantManager(const TenantConfig& config);

    [[nodiscard]] std::shared_ptr<TenantContext> resolve(const std::string& tenant_id) const;

    void register_tenant(std::string id, std::shared_ptr<TenantContext> ctx);

    void reload_tenants(std::unordered_map<std::string, std::shared_ptr<TenantContext>> tenants);

    [[nodiscard]] size_t tenant_count() const;

    bool remove_tenant(const std::string& id);
    [[nodiscard]] std::vector<std::string> list_tenants() const;
    [[nodiscard]] std::shared_ptr<TenantContext> get_tenant(const std::string& id) const;

    [[nodiscard]] const TenantConfig& config() const { return config_; }

private:
    TenantConfig config_;
    // RCU: readers get shared_ptr snapshot, writers swap entire map
    std::shared_ptr<const std::unordered_map<std::string, std::shared_ptr<TenantContext>>> tenants_;
    mutable std::shared_mutex mutex_;
};

} // namespace sqlproxy
