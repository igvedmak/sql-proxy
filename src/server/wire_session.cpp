#include "server/wire_session.hpp"
#include "core/utils.hpp"

#include <format>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

namespace sqlproxy {

WireSession::WireSession(int fd, std::string remote_addr,
                         std::shared_ptr<Pipeline> pipeline,
                         std::function<std::optional<UserInfo>(const std::string&)> user_lookup,
                         bool require_password)
    : fd_(fd),
      remote_addr_(std::move(remote_addr)),
      state_(State::WAIT_STARTUP),
      pipeline_(std::move(pipeline)),
      user_lookup_(std::move(user_lookup)),
      require_password_(require_password) {
    read_buffer_.reserve(8192);
}

void WireSession::run() {
    while (state_ != State::CLOSED) {
        if (state_ == State::WAIT_STARTUP) {
            // Startup message has no type byte: length(4) + payload
            std::vector<uint8_t> payload;
            if (!read_startup(payload)) {
                state_ = State::CLOSED;
                break;
            }
            handle_startup(payload);

        } else {
            // Regular message: type(1) + length(4) + payload
            WireFrame frame;
            if (!read_frame(frame)) {
                state_ = State::CLOSED;
                break;
            }

            if (frame.type == wire::MSG_TERMINATE) {
                state_ = State::CLOSED;
                break;
            }

            if (state_ == State::WAIT_PASSWORD) {
                handle_password(frame);
            } else if (state_ == State::READY) {
                if (frame.type == wire::MSG_QUERY) {
                    handle_query(frame);
                }
                // Ignore other message types for now (Parse/Bind/Execute/Sync)
            }
        }
    }

    close(fd_);
}

bool WireSession::read_frame(WireFrame& frame) {
    // Read type byte
    uint8_t type_byte;
    ssize_t n = recv(fd_, &type_byte, 1, MSG_WAITALL);
    if (n <= 0) return false;
    frame.type = static_cast<char>(type_byte);

    // Read length (4 bytes, includes itself)
    uint8_t len_buf[4];
    n = recv(fd_, len_buf, 4, MSG_WAITALL);
    if (n != 4) return false;

    int32_t length = WireBuffer::read_int32(len_buf);
    if (length < 4 || length > 1048576) return false;  // Max 1MB

    // Read payload
    int32_t payload_len = length - 4;
    frame.payload.resize(payload_len);
    if (payload_len > 0) {
        n = recv(fd_, frame.payload.data(), payload_len, MSG_WAITALL);
        if (n != payload_len) return false;
    }

    return true;
}

bool WireSession::read_startup(std::vector<uint8_t>& payload) {
    // Read length (4 bytes, includes itself)
    uint8_t len_buf[4];
    ssize_t n = recv(fd_, len_buf, 4, MSG_WAITALL);
    if (n != 4) return false;

    int32_t length = WireBuffer::read_int32(len_buf);
    if (length < 8 || length > 10000) return false;

    // Read remaining bytes
    payload.resize(length - 4);
    n = recv(fd_, payload.data(), length - 4, MSG_WAITALL);
    if (n != length - 4) return false;

    return true;
}

bool WireSession::send(const std::vector<uint8_t>& data) {
    return send(data.data(), data.size());
}

bool WireSession::send(const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(fd_, data + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

void WireSession::handle_startup(const std::vector<uint8_t>& payload) {
    auto startup = parse_startup_message(payload);
    if (!startup) {
        send_error("Invalid startup message");
        state_ = State::CLOSED;
        return;
    }

    // Check for SSL request (protocol 80877103)
    if (startup->protocol_version == 80877103) {
        // Send 'N' to indicate no SSL
        uint8_t no_ssl = 'N';
        send(&no_ssl, 1);
        state_ = State::WAIT_STARTUP;  // Client will retry with normal startup
        return;
    }

    user_ = startup->user;
    database_ = startup->database.empty() ? user_ : startup->database;

    // Validate user
    auto user_info = user_lookup_(user_);
    if (!user_info) {
        send_error(std::format("Unknown user: {}", user_), "28P01");
        state_ = State::CLOSED;
        return;
    }

    roles_ = user_info->roles;

    if (require_password_ && !user_info->api_key.empty()) {
        // Request cleartext password
        expected_password_ = user_info->api_key;
        send(WireWriter::auth_cleartext());
        state_ = State::WAIT_PASSWORD;
    } else {
        // No password required — send auth OK
        send(WireWriter::auth_ok());
        send(WireWriter::parameter_status("server_version", "15.0 (SQL Proxy)"));
        send(WireWriter::parameter_status("server_encoding", "UTF8"));
        send(WireWriter::parameter_status("client_encoding", "UTF8"));
        send(WireWriter::parameter_status("DateStyle", "ISO, MDY"));
        send(WireWriter::backend_key_data(static_cast<int32_t>(getpid()), 0));
        send(WireWriter::ready_for_query());
        state_ = State::READY;

        utils::log::info(std::format("Wire: {} connected as {} to {}",
            remote_addr_, user_, database_));
    }
}

void WireSession::handle_password(const WireFrame& frame) {
    if (frame.type != wire::MSG_PASSWORD) {
        send_error("Expected password message");
        state_ = State::CLOSED;
        return;
    }

    std::string password = WireBuffer::read_string(frame.payload.data(), frame.payload.size());

    if (password != expected_password_) {
        send_error("Password authentication failed", "28P01");
        state_ = State::CLOSED;
        return;
    }

    send(WireWriter::auth_ok());
    send(WireWriter::parameter_status("server_version", "15.0 (SQL Proxy)"));
    send(WireWriter::parameter_status("server_encoding", "UTF8"));
    send(WireWriter::parameter_status("client_encoding", "UTF8"));
    send(WireWriter::parameter_status("DateStyle", "ISO, MDY"));
    send(WireWriter::backend_key_data(static_cast<int32_t>(getpid()), 0));
    send(WireWriter::ready_for_query());
    state_ = State::READY;

    utils::log::info(std::format("Wire: {} authenticated as {} to {}",
        remote_addr_, user_, database_));
}

void WireSession::handle_query(const WireFrame& frame) {
    std::string sql = parse_query_message(frame);

    if (sql.empty()) {
        send(WireWriter::empty_query_response());
        send(WireWriter::ready_for_query());
        return;
    }

    // Build proxy request
    ProxyRequest request;
    request.user = user_;
    request.roles = roles_;
    request.sql = sql;
    request.database = database_;
    request.source_ip = remote_addr_;

    // Execute through pipeline
    auto response = pipeline_->execute(request);

    // Send result back through wire protocol
    send_query_result(response);
    send(WireWriter::ready_for_query());
}

void WireSession::send_query_result(const ProxyResponse& response) {
    if (!response.success) {
        send_error(response.error_message);
        return;
    }

    if (!response.result.has_value()) {
        send(WireWriter::command_complete("SELECT 0"));
        return;
    }

    const auto& result = *response.result;

    // RowDescription
    send(WireWriter::row_description(result.column_names, result.column_type_oids));

    // DataRows
    for (const auto& row : result.rows) {
        send(WireWriter::data_row(row));
    }

    // CommandComplete
    std::string tag = std::format("SELECT {}", result.rows.size());
    send(WireWriter::command_complete(tag));
}

void WireSession::send_error(const std::string& message, const std::string& sqlstate) {
    send(WireWriter::error_response("ERROR", sqlstate, message));
}

} // namespace sqlproxy
