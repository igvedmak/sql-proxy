#pragma once

#include "config/config_loader.hpp"
#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <string>
#include <thread>

namespace sqlproxy {

/**
 * @brief Background config file watcher with hot-reload support
 *
 * Monitors a TOML config file for changes using filesystem modification time.
 * When a change is detected:
 * 1. Re-parses the config file via ConfigLoader
 * 2. Validates the new config (parse must succeed)
 * 3. Invokes the reload callback with the new ProxyConfig
 *
 * The callback runs on the watcher thread. Components should use RCU
 * or shared_mutex internally to apply changes without blocking request threads.
 *
 * Design:
 * - Polling-based (portable, works in Docker/WSL/NFS)
 * - Configurable poll interval (default: 5 seconds)
 * - Failed reloads are logged but don't crash the proxy
 * - Stop-token aware sleep for fast shutdown
 *
 * Thread-safety: The watcher runs on a single std::jthread. The callback
 * must be thread-safe (called from watcher thread, not request threads).
 */
class ConfigWatcher {
public:
    using ReloadCallback = std::function<void(const ProxyConfig& new_config)>;

    /**
     * @brief Construct watcher for a config file
     * @param config_path Path to the TOML config file
     * @param poll_interval How often to check for changes
     */
    explicit ConfigWatcher(
        std::string config_path,
        std::chrono::seconds poll_interval = std::chrono::seconds{5});

    ~ConfigWatcher();

    // Non-copyable, non-movable
    ConfigWatcher(const ConfigWatcher&) = delete;
    ConfigWatcher& operator=(const ConfigWatcher&) = delete;

    /**
     * @brief Set the callback invoked when config changes
     * @param callback Called with the new ProxyConfig on successful reload
     */
    void set_callback(ReloadCallback callback);

    /**
     * @brief Start watching (spawns background thread)
     */
    void start();

    /**
     * @brief Stop watching (joins background thread)
     */
    void stop();

    [[nodiscard]] bool is_running() const { return running_.load(); }

private:
    void watch_loop(std::stop_token stop);

    std::string config_path_;
    std::chrono::seconds poll_interval_;
    ReloadCallback callback_;

    std::filesystem::file_time_type last_mtime_{};
    std::atomic<bool> running_{false};
    std::jthread watch_thread_;
};

} // namespace sqlproxy
