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
                         bool require_password,
                         SSL_CTX* ssl_ctx)
    : fd_(fd),
      remote_addr_(std::move(remote_addr)),
      state_(State::WAIT_STARTUP),
      pipeline_(std::move(pipeline)),
      user_lookup_(std::move(user_lookup)),
      require_password_(require_password),
      ssl_ctx_(ssl_ctx) {
    read_buffer_.reserve(8192);
}

// ---- Unified I/O layer --------------------------------------------------

bool WireSession::do_read_exact(void* buf, size_t len) {
    if (ssl_conn_) {
        return ssl_conn_->read_exact(buf, len);
    }
    // Raw socket: recv with MSG_WAITALL for exact read
    auto* ptr = static_cast<uint8_t*>(buf);
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = recv(fd_, ptr, remaining, MSG_WAITALL);
        if (n <= 0) return false;
        ptr += n;
        remaining -= static_cast<size_t>(n);
    }
    return true;
}

bool WireSession::do_write(const void* buf, size_t len) {
    if (ssl_conn_) {
        return ssl_conn_->write_all(buf, len);
    }
    // Raw socket
    auto* ptr = static_cast<const uint8_t*>(buf);
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(fd_, ptr + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

// ---- Session main loop ---------------------------------------------------

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
    if (!do_read_exact(&type_byte, 1)) return false;
    frame.type = static_cast<char>(type_byte);

    // Read length (4 bytes, includes itself)
    uint8_t len_buf[4];
    if (!do_read_exact(len_buf, 4)) return false;

    const int32_t length = WireBuffer::read_int32(len_buf);
    if (length < 4 || length > 1048576) return false;  // Max 1MB

    // Read payload
    const int32_t payload_len = length - 4;
    frame.payload.resize(payload_len);
    if (payload_len > 0) {
        if (!do_read_exact(frame.payload.data(), payload_len)) return false;
    }

    return true;
}

bool WireSession::read_startup(std::vector<uint8_t>& payload) {
    // Read length (4 bytes, includes itself)
    uint8_t len_buf[4];
    if (!do_read_exact(len_buf, 4)) return false;

    const int32_t length = WireBuffer::read_int32(len_buf);
    if (length < 8 || length > 10000) return false;

    // Read remaining bytes
    payload.resize(length - 4);
    if (!do_read_exact(payload.data(), length - 4)) return false;

    return true;
}

bool WireSession::send(const std::vector<uint8_t>& data) {
    return do_write(data.data(), data.size());
}

bool WireSession::send(const uint8_t* data, size_t len) {
    return do_write(data, len);
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
        if (ssl_ctx_) {
            // TLS enabled: send 'S' and upgrade connection
            uint8_t yes_ssl = 'S';
            // Must use raw socket for the 'S' byte (before TLS handshake)
            const ssize_t n = ::send(fd_, &yes_ssl, 1, MSG_NOSIGNAL);
            if (n != 1) {
                state_ = State::CLOSED;
                return;
            }

            // Perform TLS handshake
            ssl_conn_ = std::make_unique<SslConnection>(fd_, ssl_ctx_);
            if (!ssl_conn_->is_valid()) {
                utils::log::warn(std::format("Wire: TLS handshake failed from {}", remote_addr_));
                ssl_conn_.reset();
                state_ = State::CLOSED;
                return;
            }

            utils::log::info(std::format("Wire: TLS established with {}", remote_addr_));
        } else {
            // TLS not configured: send 'N' (no SSL)
            uint8_t no_ssl = 'N';
            const ssize_t n = ::send(fd_, &no_ssl, 1, MSG_NOSIGNAL);
            if (n != 1) {
                state_ = State::CLOSED;
                return;
            }
        }
        // Client will retry with normal startup message
        state_ = State::WAIT_STARTUP;
        return;
    }

    user_ = startup->user;
    database_ = startup->database.empty() ? user_ : startup->database;

    // Validate user
    const auto user_info = user_lookup_(user_);
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

        utils::log::info(std::format("Wire: {} connected as {} to {}{}",
            remote_addr_, user_, database_,
            ssl_conn_ ? " (TLS)" : ""));
    }
}

void WireSession::handle_password(const WireFrame& frame) {
    if (frame.type != wire::MSG_PASSWORD) {
        send_error("Expected password message");
        state_ = State::CLOSED;
        return;
    }

    const std::string password = WireBuffer::read_string(frame.payload.data(), frame.payload.size());

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

    utils::log::info(std::format("Wire: {} authenticated as {} to {}{}",
        remote_addr_, user_, database_,
        ssl_conn_ ? " (TLS)" : ""));
}

void WireSession::handle_query(const WireFrame& frame) {
    const std::string sql = parse_query_message(frame);

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
    const auto response = pipeline_->execute(request);

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
