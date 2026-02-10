#include "security/vault_key_manager.hpp"
#include "server/http_constants.hpp"
#include "core/utils.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include "../third_party/cpp-httplib/httplib.h"
#pragma GCC diagnostic pop

#include <format>

namespace sqlproxy {

VaultKeyManager::VaultKeyManager(VaultKeyManagerConfig config)
    : config_(std::move(config)) {

    // Read token from environment if not set in config
    if (config_.vault_token.empty()) {
        const char* env_token = std::getenv("VAULT_TOKEN");
        if (env_token) {
            config_.vault_token = env_token;
        }
    }

    // Initial cache load
    refresh_cache();
}

std::optional<IKeyManager::KeyInfo> VaultKeyManager::get_active_key() const {
    {
        std::shared_lock lock(cache_mutex_);
        const auto elapsed = std::chrono::steady_clock::now() - last_refresh_;
        if (elapsed < std::chrono::seconds(config_.cache_ttl_seconds) && !active_key_id_.empty()) {
            if (const auto it = key_cache_.find(active_key_id_); it != key_cache_.end()) {
                return it->second;
            }
        }
    }

    refresh_cache();

    std::shared_lock lock(cache_mutex_);
    if (!active_key_id_.empty()) {
        if (const auto it = key_cache_.find(active_key_id_); it != key_cache_.end()) {
            return it->second;
        }
    }
    return std::nullopt;
}

std::optional<IKeyManager::KeyInfo> VaultKeyManager::get_key(const std::string& key_id) const {
    {
        std::shared_lock lock(cache_mutex_);
        if (const auto it = key_cache_.find(key_id); it != key_cache_.end()) {
            return it->second;
        }
    }

    refresh_cache();

    std::shared_lock lock(cache_mutex_);
    if (const auto it = key_cache_.find(key_id); it != key_cache_.end()) {
        return it->second;
    }
    return std::nullopt;
}

bool VaultKeyManager::rotate_key() {
    const std::string path = std::format("/v1/{}/keys/{}/rotate", config_.mount, config_.key_name);
    const std::string response = vault_api_post(path);

    if (response.empty()) {
        utils::log::error("Vault: key rotation failed — empty response");
        return false;
    }

    refresh_cache();
    utils::log::info(std::format("Vault: key '{}' rotated successfully", config_.key_name));
    return true;
}

size_t VaultKeyManager::key_count() const {
    std::shared_lock lock(cache_mutex_);
    return key_cache_.size();
}

void VaultKeyManager::refresh_cache() const {
    const std::string path = std::format("/v1/{}/keys/{}", config_.mount, config_.key_name);
    const std::string response = vault_api_get(path);

    if (response.empty()) {
        utils::log::error("Vault: failed to fetch key info");
        return;
    }

    // Parse response to extract key versions
    // Vault Transit returns: {"data": {"name": "...", "latest_version": N, "keys": {"1": {...}, "2": {...}}}}
    // We generate local key bytes from the key ID + version (Vault Transit doesn't export raw keys,
    // so in production this would use Vault's encrypt/decrypt endpoints directly).
    // For this implementation, we use the key metadata to track versions.

    std::unique_lock lock(cache_mutex_);

    // Simple parsing: find latest_version
    auto lv_pos = response.find("\"latest_version\"");
    if (lv_pos != std::string::npos) {
        lv_pos = response.find(':', lv_pos);
        if (lv_pos != std::string::npos) {
            ++lv_pos;
            while (lv_pos < response.size() && response[lv_pos] == ' ') ++lv_pos;
            const auto end = response.find_first_of(",}", lv_pos);
            const std::string version_str = response.substr(lv_pos, end - lv_pos);
            try {
                const int latest = std::stoi(version_str);
                active_key_id_ = std::format("v{}", latest);

                // Ensure all versions exist in cache
                for (int v = 1; v <= latest; ++v) {
                    std::string kid = std::format("v{}", v);
                    if (key_cache_.find(kid) == key_cache_.end()) {
                        KeyInfo ki;
                        ki.key_id = kid;
                        ki.key_bytes.resize(32, 0);  // Placeholder — real impl uses Vault encrypt/decrypt
                        ki.active = (v == latest);
                        key_cache_[kid] = std::move(ki);
                    } else {
                        key_cache_[kid].active = (v == latest);
                    }
                }
            } catch (const std::exception& e) {
                utils::log::error(std::format("Vault: failed to parse version '{}': {}", version_str, e.what()));
            }
        }
    }

    last_refresh_ = std::chrono::steady_clock::now();
}

std::string VaultKeyManager::vault_api_get(const std::string& path) const {
    if (config_.vault_addr.empty()) return "";

    try {
        httplib::Client cli(config_.vault_addr);
        cli.set_connection_timeout(5);
        cli.set_read_timeout(5);

        const httplib::Headers headers = {
            {"X-Vault-Token", config_.vault_token}
        };

        const auto res = cli.Get(path, headers);
        if (res && res->status == httplib::StatusCode::OK_200) {
            return res->body;
        }
    } catch (...) {
        // Connection failure
    }
    return "";
}

std::string VaultKeyManager::vault_api_post(const std::string& path) const {
    if (config_.vault_addr.empty()) return "";

    try {
        httplib::Client cli(config_.vault_addr);
        cli.set_connection_timeout(5);
        cli.set_read_timeout(5);

        const httplib::Headers headers = {
            {"X-Vault-Token", config_.vault_token}
        };

        const auto res = cli.Post(path, headers, "", http::kJsonContentType);
        if (res && (res->status == httplib::StatusCode::OK_200 || res->status == httplib::StatusCode::NoContent_204)) {
            return res->body.empty() ? "{}" : res->body;
        }
    } catch (...) {
        // Connection failure
    }
    return "";
}

} // namespace sqlproxy
