#pragma once

#include "core/pipeline.hpp"
#include "server/http_server.hpp"  // UserInfo
#include <atomic>
#include <memory>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace sqlproxy {

struct BinaryRpcConfig {
    bool enabled = false;
    std::string host = "0.0.0.0";
    uint16_t port = 9090;
    uint32_t max_connections = 50;
};

// Binary RPC frame format:
// [4-byte length][1-byte msg_type][payload]
// msg_type: 0x01 = QueryRequest, 0x02 = QueryResponse, 0xFF = Error
namespace rpc {
    constexpr uint8_t MSG_QUERY_REQUEST = 0x01;
    constexpr uint8_t MSG_QUERY_RESPONSE = 0x02;
    constexpr uint8_t MSG_ERROR = 0xFF;
}

// Serialized query request
struct BinaryQueryRequest {
    std::string user;
    std::string database;
    std::string sql;
};

class BinaryRpcServer {
public:
    BinaryRpcServer(std::shared_ptr<Pipeline> pipeline,
                    const BinaryRpcConfig& config,
                    std::unordered_map<std::string, UserInfo> users);

    ~BinaryRpcServer();

    void start();
    void stop();

    void update_users(std::unordered_map<std::string, UserInfo> users);

    [[nodiscard]] uint32_t active_connections() const {
        return active_connections_.load();
    }

private:
    void accept_loop();
    void handle_connection(int client_fd, std::string remote_addr);

    // Frame I/O
    static bool read_frame(int fd, uint8_t& msg_type, std::vector<uint8_t>& payload);
    static bool send_frame(int fd, uint8_t msg_type, const std::vector<uint8_t>& payload);

    // Serialize/deserialize
    static std::optional<BinaryQueryRequest> deserialize_request(const std::vector<uint8_t>& payload);
    static std::vector<uint8_t> serialize_response(const ProxyResponse& response);
    static std::vector<uint8_t> serialize_error(const std::string& message);

    std::optional<UserInfo> lookup_user(const std::string& username) const;

    std::shared_ptr<Pipeline> pipeline_;
    BinaryRpcConfig config_;

    std::unordered_map<std::string, UserInfo> users_;
    mutable std::shared_mutex users_mutex_;

    int server_fd_ = -1;
    std::atomic<bool> running_{false};
    std::atomic<uint32_t> active_connections_{0};

    std::jthread accept_thread_;
    std::vector<std::jthread> workers_;
};

} // namespace sqlproxy
