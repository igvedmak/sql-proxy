#include "config/config_watcher.hpp"
#include "core/utils.hpp"

#include <format>

namespace sqlproxy {

ConfigWatcher::ConfigWatcher(std::string config_path, std::chrono::seconds poll_interval)
    : config_path_(std::move(config_path)),
      poll_interval_(poll_interval) {
    // Record initial modification time
    std::error_code ec;
    last_mtime_ = std::filesystem::last_write_time(config_path_, ec);
    if (ec) {
        utils::log::warn(std::format("Config watcher: cannot stat {}: {}", config_path_, ec.message()));
    }
}

ConfigWatcher::~ConfigWatcher() {
    stop();
}

void ConfigWatcher::set_callback(ReloadCallback callback) {
    callback_ = std::move(callback);
}

void ConfigWatcher::start() {
    if (running_.load()) return;
    running_.store(true);
    watch_thread_ = std::jthread([this](std::stop_token stop) {
        watch_loop(std::move(stop));
    });
    utils::log::info(std::format("Config watcher started: polling {} every {}s",
                                  config_path_, poll_interval_.count()));
}

void ConfigWatcher::stop() {
    if (!running_.load()) return;
    running_.store(false);
    if (watch_thread_.joinable()) {
        watch_thread_.request_stop();
        watch_thread_.join();
    }
    utils::log::info("Config watcher stopped");
}

void ConfigWatcher::watch_loop(std::stop_token stop) {
    while (!stop.stop_requested()) {
        // Sleep in 100ms increments for responsive shutdown
        for (int i = 0; i < poll_interval_.count() * 10 && !stop.stop_requested(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
        }

        if (stop.stop_requested()) break;

        // Check file modification time
        std::error_code ec;
        auto current_mtime = std::filesystem::last_write_time(config_path_, ec);
        if (ec) {
            utils::log::warn(std::format("Config watcher: cannot stat {}: {}",
                                          config_path_, ec.message()));
            continue;
        }

        if (current_mtime == last_mtime_) {
            continue;  // No change
        }

        utils::log::info(std::format("Config file changed: {}", config_path_));
        last_mtime_ = current_mtime;

        // Small delay to ensure the file is fully written (atomic rename may be instant,
        // but editors that write-in-place may have a brief incomplete window)
        std::this_thread::sleep_for(std::chrono::milliseconds{100});

        // Reload config
        auto result = ConfigLoader::load_from_file(config_path_);
        if (!result.success) {
            utils::log::error(std::format("Config reload failed (keeping old config): {}",
                                           result.error_message));
            continue;
        }

        // Invoke callback
        if (callback_) {
            try {
                callback_(result.config);
                utils::log::info("Config reloaded successfully");
            } catch (const std::exception& e) {
                utils::log::error(std::format("Config reload callback error: {}", e.what()));
            }
        }
    }
}

} // namespace sqlproxy
