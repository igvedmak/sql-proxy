#include "server/binary_rpc_server.hpp"
#include "core/utils.hpp"

#include <format>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

namespace sqlproxy {

BinaryRpcServer::BinaryRpcServer(std::shared_ptr<Pipeline> pipeline,
                                 const BinaryRpcConfig& config,
                                 std::unordered_map<std::string, UserInfo> users)
    : pipeline_(std::move(pipeline)),
      config_(config),
      users_(std::move(users)) {}

BinaryRpcServer::~BinaryRpcServer() {
    stop();
}

void BinaryRpcServer::start() {
    if (running_.load()) return;

    server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        throw std::runtime_error(std::format("BinaryRPC: socket() failed: {}", strerror(errno)));
    }

    int opt = 1;
    setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.port);
    inet_aton(config_.host.c_str(), &addr.sin_addr);

    if (bind(server_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(server_fd_);
        throw std::runtime_error(std::format("BinaryRPC: bind({}:{}) failed: {}",
            config_.host, config_.port, strerror(errno)));
    }

    if (listen(server_fd_, 64) < 0) {
        close(server_fd_);
        throw std::runtime_error(std::format("BinaryRPC: listen() failed: {}", strerror(errno)));
    }

    running_.store(true);
    accept_thread_ = std::jthread([this](std::stop_token) { accept_loop(); });

    utils::log::info(std::format("Binary RPC server listening on {}:{}",
        config_.host, config_.port));
}

void BinaryRpcServer::stop() {
    if (!running_.exchange(false)) return;

    if (server_fd_ >= 0) {
        shutdown(server_fd_, SHUT_RDWR);
        close(server_fd_);
        server_fd_ = -1;
    }

    if (accept_thread_.joinable()) {
        accept_thread_.request_stop();
        accept_thread_.join();
    }

    for (auto& w : workers_) {
        if (w.joinable()) w.join();
    }
    workers_.clear();

    utils::log::info("Binary RPC server stopped");
}

void BinaryRpcServer::accept_loop() {
    while (running_.load()) {
        struct sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);

        int client_fd = accept(server_fd_,
            reinterpret_cast<struct sockaddr*>(&client_addr), &addr_len);

        if (client_fd < 0) {
            if (!running_.load()) break;
            continue;
        }

        if (active_connections_.load() >= config_.max_connections) {
            close(client_fd);
            continue;
        }

        std::string remote_addr = std::format("{}:{}",
            inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        active_connections_.fetch_add(1);
        workers_.emplace_back([this, client_fd, addr = std::move(remote_addr)]() {
            handle_connection(client_fd, std::move(addr));
            active_connections_.fetch_sub(1);
        });
    }
}

void BinaryRpcServer::handle_connection(int client_fd, std::string /*remote_addr*/) {
    while (running_.load()) {
        uint8_t msg_type;
        std::vector<uint8_t> payload;

        if (!read_frame(client_fd, msg_type, payload)) {
            break;
        }

        if (msg_type == rpc::MSG_QUERY_REQUEST) {
            auto req = deserialize_request(payload);
            if (!req) {
                auto err = serialize_error("Invalid request format");
                send_frame(client_fd, rpc::MSG_ERROR, err);
                continue;
            }

            // Validate user
            auto user_info = lookup_user(req->user);
            if (!user_info) {
                auto err = serialize_error(std::format("Unknown user: {}", req->user));
                send_frame(client_fd, rpc::MSG_ERROR, err);
                continue;
            }

            // Build and execute proxy request
            ProxyRequest proxy_req;
            proxy_req.user = req->user;
            proxy_req.roles = user_info->roles;
            proxy_req.sql = req->sql;
            proxy_req.database = req->database;

            auto response = pipeline_->execute(proxy_req);

            auto resp_data = serialize_response(response);
            send_frame(client_fd, rpc::MSG_QUERY_RESPONSE, resp_data);
        }
    }

    close(client_fd);
}

bool BinaryRpcServer::read_frame(int fd, uint8_t& msg_type, std::vector<uint8_t>& payload) {
    // Read 4-byte length
    uint8_t len_buf[4];
    ssize_t n = recv(fd, len_buf, 4, MSG_WAITALL);
    if (n != 4) return false;

    uint32_t length = (static_cast<uint32_t>(len_buf[0]) << 24) |
                      (static_cast<uint32_t>(len_buf[1]) << 16) |
                      (static_cast<uint32_t>(len_buf[2]) << 8) |
                       static_cast<uint32_t>(len_buf[3]);

    if (length < 1 || length > 10485760) return false;  // Max 10MB

    // Read msg_type
    n = recv(fd, &msg_type, 1, MSG_WAITALL);
    if (n != 1) return false;

    // Read payload
    uint32_t payload_len = length - 1;
    payload.resize(payload_len);
    if (payload_len > 0) {
        n = recv(fd, payload.data(), payload_len, MSG_WAITALL);
        if (n != static_cast<ssize_t>(payload_len)) return false;
    }

    return true;
}

bool BinaryRpcServer::send_frame(int fd, uint8_t msg_type, const std::vector<uint8_t>& payload) {
    uint32_t length = static_cast<uint32_t>(1 + payload.size());

    uint8_t header[5];
    header[0] = static_cast<uint8_t>((length >> 24) & 0xFF);
    header[1] = static_cast<uint8_t>((length >> 16) & 0xFF);
    header[2] = static_cast<uint8_t>((length >> 8) & 0xFF);
    header[3] = static_cast<uint8_t>(length & 0xFF);
    header[4] = msg_type;

    ssize_t n = ::send(fd, header, 5, MSG_NOSIGNAL);
    if (n != 5) return false;

    if (!payload.empty()) {
        size_t sent = 0;
        while (sent < payload.size()) {
            n = ::send(fd, payload.data() + sent, payload.size() - sent, MSG_NOSIGNAL);
            if (n <= 0) return false;
            sent += static_cast<size_t>(n);
        }
    }

    return true;
}

std::optional<BinaryQueryRequest> BinaryRpcServer::deserialize_request(
    const std::vector<uint8_t>& payload) {
    // Simple format: [2-byte user_len][user][2-byte db_len][database][rest=sql]
    if (payload.size() < 6) return std::nullopt;

    size_t pos = 0;

    // User
    uint16_t user_len = (static_cast<uint16_t>(payload[pos]) << 8) | payload[pos + 1];
    pos += 2;
    if (pos + user_len > payload.size()) return std::nullopt;
    std::string user(reinterpret_cast<const char*>(payload.data() + pos), user_len);
    pos += user_len;

    // Database
    if (pos + 2 > payload.size()) return std::nullopt;
    uint16_t db_len = (static_cast<uint16_t>(payload[pos]) << 8) | payload[pos + 1];
    pos += 2;
    if (pos + db_len > payload.size()) return std::nullopt;
    std::string database(reinterpret_cast<const char*>(payload.data() + pos), db_len);
    pos += db_len;

    // SQL (remainder)
    std::string sql(reinterpret_cast<const char*>(payload.data() + pos), payload.size() - pos);

    return BinaryQueryRequest{std::move(user), std::move(database), std::move(sql)};
}

std::vector<uint8_t> BinaryRpcServer::serialize_response(const ProxyResponse& response) {
    // Simple JSON serialization for response payload
    std::string json;
    if (response.success && response.result.has_value()) {
        const auto& result = *response.result;
        json = std::format(R"({{"success":true,"columns":[)", "");
        for (size_t i = 0; i < result.column_names.size(); ++i) {
            if (i > 0) json += ",";
            json += std::format(R"("{}")", result.column_names[i]);
        }
        json += "],\"rows\":[";
        for (size_t i = 0; i < result.rows.size(); ++i) {
            if (i > 0) json += ",";
            json += "[";
            for (size_t j = 0; j < result.rows[i].size(); ++j) {
                if (j > 0) json += ",";
                json += std::format(R"("{}")", result.rows[i][j]);
            }
            json += "]";
        }
        json += "]}";
    } else {
        json = std::format(R"({{"success":false,"error":"{}"}})", response.error_message);
    }

    return std::vector<uint8_t>(json.begin(), json.end());
}

std::vector<uint8_t> BinaryRpcServer::serialize_error(const std::string& message) {
    std::string json = std::format(R"({{"error":"{}"}})", message);
    return std::vector<uint8_t>(json.begin(), json.end());
}

std::optional<UserInfo> BinaryRpcServer::lookup_user(const std::string& username) const {
    std::shared_lock lock(users_mutex_);
    const auto it = users_.find(username);
    if (it != users_.end()) return it->second;
    if (users_.empty()) return UserInfo(std::string(username), {"user"});
    return std::nullopt;
}

void BinaryRpcServer::update_users(std::unordered_map<std::string, UserInfo> users) {
    std::unique_lock lock(users_mutex_);
    users_ = std::move(users);
}

} // namespace sqlproxy
