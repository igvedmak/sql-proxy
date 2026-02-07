#include "config/local_config_store.hpp"
#include "config/config_loader.hpp"

namespace sqlproxy {

LocalConfigStore::LocalConfigStore(
    std::string config_path, std::chrono::seconds poll_interval)
    : config_path_(std::move(config_path)),
      watcher_(std::make_unique<ConfigWatcher>(config_path_, poll_interval)) {}

std::optional<ProxyConfig> LocalConfigStore::load() {
    const auto result = ConfigLoader::load_from_file(config_path_);
    if (!result.success) return std::nullopt;
    return std::move(result.config);
}

void LocalConfigStore::watch(ChangeCallback callback) {
    watcher_->set_callback(std::move(callback));
    watcher_->start();
}

void LocalConfigStore::stop() {
    watcher_->stop();
}

} // namespace sqlproxy
