#pragma once

#include "server/wire_protocol.hpp"
#include "server/http_server.hpp"  // UserInfo
#include "core/pipeline.hpp"
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <functional>

namespace sqlproxy {

struct WireProtocolConfig {
    bool enabled = false;
    std::string host = "0.0.0.0";
    uint16_t port = 5433;
    uint32_t max_connections = 100;
    uint32_t thread_pool_size = 4;
    bool require_password = false;
};

// Per-connection state machine for PostgreSQL wire protocol
class WireSession {
public:
    enum class State {
        WAIT_STARTUP,
        WAIT_PASSWORD,
        READY,
        CLOSED
    };

    WireSession(int fd, std::string remote_addr,
                std::shared_ptr<Pipeline> pipeline,
                std::function<std::optional<UserInfo>(const std::string&)> user_lookup,
                bool require_password = false);

    // Run the session (blocking, called from worker thread)
    void run();

    [[nodiscard]] State state() const { return state_; }
    [[nodiscard]] const std::string& user() const { return user_; }
    [[nodiscard]] const std::string& database() const { return database_; }

private:
    // Read a complete frame from the socket
    [[nodiscard]] bool read_frame(WireFrame& frame);

    // Read startup message (no type byte, just length + payload)
    [[nodiscard]] bool read_startup(std::vector<uint8_t>& payload);

    // Send bytes to client
    bool send(const std::vector<uint8_t>& data);
    bool send(const uint8_t* data, size_t len);

    // State handlers
    void handle_startup(const std::vector<uint8_t>& payload);
    void handle_password(const WireFrame& frame);
    void handle_query(const WireFrame& frame);

    // Send query result back through wire protocol
    void send_query_result(const ProxyResponse& response);
    void send_error(const std::string& message, const std::string& sqlstate = "42000");

    int fd_;
    std::string remote_addr_;
    State state_;
    std::string user_;
    std::string database_;
    std::vector<std::string> roles_;
    std::shared_ptr<Pipeline> pipeline_;
    std::function<std::optional<UserInfo>(const std::string&)> user_lookup_;
    bool require_password_;
    std::string expected_password_;  // For cleartext auth

    // Buffer for reading
    std::vector<uint8_t> read_buffer_;
};

} // namespace sqlproxy
