#include "security/env_key_manager.hpp"
#include "core/utils.hpp"

#include <cstdlib>
#include <format>

namespace sqlproxy {

EnvKeyManager::EnvKeyManager(const std::string& env_var_name) {
    const char* hex_key = std::getenv(env_var_name.c_str());
    if (!hex_key || std::string(hex_key).empty()) {
        utils::log::warn(std::format("EnvKeyManager: environment variable '{}' not set", env_var_name));
        return;
    }

    std::string hex(hex_key);

    // Hex decode
    if (hex.size() < 2 || hex.size() % 2 != 0) {
        utils::log::error(std::format("EnvKeyManager: '{}' must be hex-encoded (even length)", env_var_name));
        return;
    }

    key_.key_bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        try {
            uint8_t byte = static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16));
            key_.key_bytes.push_back(byte);
        } catch (...) {
            utils::log::error(std::format("EnvKeyManager: invalid hex at position {}", i));
            key_.key_bytes.clear();
            return;
        }
    }

    if (key_.key_bytes.size() != 32) {
        utils::log::warn(std::format("EnvKeyManager: key is {} bytes (expected 32 for AES-256)",
            key_.key_bytes.size()));
    }

    key_.key_id = "env-key-1";
    key_.created_at = std::chrono::system_clock::now();
    key_.active = true;
    valid_ = true;

    utils::log::info(std::format("EnvKeyManager: loaded {}-byte key from '{}'",
        key_.key_bytes.size(), env_var_name));
}

std::optional<IKeyManager::KeyInfo> EnvKeyManager::get_active_key() const {
    if (!valid_) return std::nullopt;
    return key_;
}

std::optional<IKeyManager::KeyInfo> EnvKeyManager::get_key(const std::string& key_id) const {
    if (!valid_ || key_id != key_.key_id) return std::nullopt;
    return key_;
}

bool EnvKeyManager::rotate_key() {
    // Env-based keys don't support rotation
    utils::log::warn("EnvKeyManager: key rotation not supported — restart with new env var");
    return false;
}

size_t EnvKeyManager::key_count() const {
    return valid_ ? 1 : 0;
}

} // namespace sqlproxy
