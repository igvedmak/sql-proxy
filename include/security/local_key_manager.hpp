#pragma once

#include "security/ikey_manager.hpp"

#include <shared_mutex>

namespace sqlproxy {

class LocalKeyManager : public IKeyManager {
public:
    explicit LocalKeyManager(const std::string& key_file = "");

    [[nodiscard]] std::optional<KeyInfo> get_active_key() const override;
    [[nodiscard]] std::optional<KeyInfo> get_key(const std::string& key_id) const override;
    bool rotate_key() override;
    [[nodiscard]] size_t key_count() const override;

    // Generate a new 256-bit random key and add it as active
    bool generate_and_add_key();

private:
    std::string key_file_;
    mutable std::shared_mutex mutex_;
    std::vector<KeyInfo> keys_;
    size_t active_index_ = 0;

    void load_keys();
    void save_keys();
    static std::vector<uint8_t> generate_key();
    static std::string generate_key_id();
};

} // namespace sqlproxy
