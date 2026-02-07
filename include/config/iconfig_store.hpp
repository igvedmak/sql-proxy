#pragma once

#include <functional>
#include <optional>

namespace sqlproxy {

struct ProxyConfig;

/**
 * @brief Abstract config store interface
 *
 * Enables pluggable config backends — local file (LocalConfigStore),
 * future etcd/Consul, or in-memory for testing.
 */
class IConfigStore {
public:
    virtual ~IConfigStore() = default;

    using ChangeCallback = std::function<void(const ProxyConfig&)>;

    [[nodiscard]] virtual std::optional<ProxyConfig> load() = 0;
    virtual void watch(ChangeCallback callback) = 0;
    virtual void stop() = 0;
};

} // namespace sqlproxy
