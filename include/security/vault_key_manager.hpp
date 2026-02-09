#pragma once

#include "security/ikey_manager.hpp"
#include <chrono>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace sqlproxy {

struct VaultKeyManagerConfig {
    std::string vault_addr;              // e.g., "https://vault.example.com:8200"
    std::string vault_token;             // Auth token (or from VAULT_TOKEN env)
    std::string key_name = "sql-proxy";  // Transit key name
    std::string mount = "transit";       // Transit mount path
    int cache_ttl_seconds = 300;         // Key cache TTL
};

/**
 * @brief HashiCorp Vault Transit secrets engine key manager
 *
 * Fetches encryption keys from Vault's Transit engine via HTTP API.
 * Caches keys locally with configurable TTL for performance.
 */
class VaultKeyManager : public IKeyManager {
public:
    explicit VaultKeyManager(VaultKeyManagerConfig config);

    [[nodiscard]] std::optional<KeyInfo> get_active_key() const override;
    [[nodiscard]] std::optional<KeyInfo> get_key(const std::string& key_id) const override;
    bool rotate_key() override;
    [[nodiscard]] size_t key_count() const override;

private:
    void refresh_cache() const;
    [[nodiscard]] std::string vault_api_get(const std::string& path) const;
    [[nodiscard]] std::string vault_api_post(const std::string& path) const;

    VaultKeyManagerConfig config_;

    // Cached keys (mutable for const refresh)
    mutable std::unordered_map<std::string, KeyInfo> key_cache_;
    mutable std::string active_key_id_;
    mutable std::chrono::steady_clock::time_point last_refresh_;
    mutable std::shared_mutex cache_mutex_;
};

} // namespace sqlproxy
