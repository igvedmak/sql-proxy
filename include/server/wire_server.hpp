#pragma once

#include "server/wire_session.hpp"
#include "server/http_server.hpp"  // UserInfo
#include "core/pipeline.hpp"
#include <atomic>
#include <memory>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace sqlproxy {

class WireServer {
public:
    WireServer(std::shared_ptr<Pipeline> pipeline,
               const WireProtocolConfig& config,
               std::unordered_map<std::string, UserInfo> users);

    ~WireServer();

    // Non-blocking: spawns accept thread + worker pool
    void start();

    void stop();

    // Hot-reload users
    void update_users(std::unordered_map<std::string, UserInfo> users);

    [[nodiscard]] uint32_t active_connections() const {
        return active_connections_.load();
    }

private:
    void accept_loop();
    void handle_connection(int client_fd, std::string remote_addr);

    std::optional<UserInfo> lookup_user(const std::string& username) const;

    std::shared_ptr<Pipeline> pipeline_;
    WireProtocolConfig config_;

    // User registry (hot-reloadable)
    std::unordered_map<std::string, UserInfo> users_;
    mutable std::shared_mutex users_mutex_;

    // Server socket
    int server_fd_ = -1;
    std::atomic<bool> running_{false};
    std::atomic<uint32_t> active_connections_{0};

    // Thread management
    std::jthread accept_thread_;
    std::vector<std::jthread> workers_;
};

} // namespace sqlproxy
