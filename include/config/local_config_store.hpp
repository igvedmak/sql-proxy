#pragma once

#include "config/iconfig_store.hpp"
#include "config/config_watcher.hpp"
#include <chrono>
#include <memory>
#include <string>

namespace sqlproxy {

/**
 * @brief File-based IConfigStore wrapping ConfigWatcher + ConfigLoader
 */
class LocalConfigStore : public IConfigStore {
public:
    explicit LocalConfigStore(
        std::string config_path,
        std::chrono::seconds poll_interval = std::chrono::seconds{5});

    [[nodiscard]] std::optional<ProxyConfig> load() override;
    void watch(ChangeCallback callback) override;
    void stop() override;

private:
    std::string config_path_;
    std::unique_ptr<ConfigWatcher> watcher_;
};

} // namespace sqlproxy
