#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sqlproxy {

class IKeyManager {
public:
    virtual ~IKeyManager() = default;

    struct KeyInfo {
        std::string key_id;
        std::vector<uint8_t> key_bytes;     // 256-bit DEK
        std::chrono::system_clock::time_point created_at;
        bool active = true;

        KeyInfo() : created_at(std::chrono::system_clock::now()) {}
    };

    [[nodiscard]] virtual std::optional<KeyInfo> get_active_key() const = 0;
    [[nodiscard]] virtual std::optional<KeyInfo> get_key(const std::string& key_id) const = 0;
    virtual bool rotate_key() = 0;
    [[nodiscard]] virtual size_t key_count() const = 0;
};

} // namespace sqlproxy
