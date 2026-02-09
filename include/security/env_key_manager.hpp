#pragma once

#include "security/ikey_manager.hpp"
#include <string>

namespace sqlproxy {

/**
 * @brief Environment variable key manager
 *
 * Reads a single encryption key from an environment variable.
 * The key must be hex-encoded (64 hex chars = 32 bytes = 256-bit AES key).
 * No key rotation support — suitable for simple 12-factor apps.
 */
class EnvKeyManager : public IKeyManager {
public:
    explicit EnvKeyManager(const std::string& env_var_name = "ENCRYPTION_KEY");

    [[nodiscard]] std::optional<KeyInfo> get_active_key() const override;
    [[nodiscard]] std::optional<KeyInfo> get_key(const std::string& key_id) const override;
    bool rotate_key() override;
    [[nodiscard]] size_t key_count() const override;

private:
    KeyInfo key_;
    bool valid_ = false;
};

} // namespace sqlproxy
