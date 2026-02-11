#include "server/wire_session.hpp"
#include "auth/scram_sha256.hpp"
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
                         SSL_CTX* ssl_ctx,
                         bool prefer_scram,
                         uint32_t scram_iterations)
    : fd_(fd),
      remote_addr_(std::move(remote_addr)),
      state_(State::WAIT_STARTUP),
      pipeline_(std::move(pipeline)),
      user_lookup_(std::move(user_lookup)),
      require_password_(require_password),
      prefer_scram_(prefer_scram),
      scram_iterations_(scram_iterations),
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
            } else if (state_ == State::WAIT_SASL_INITIAL) {
                handle_sasl_initial(frame);
            } else if (state_ == State::WAIT_SASL_RESPONSE) {
                handle_sasl_response(frame);
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
        expected_password_ = user_info->api_key;

        if (prefer_scram_) {
            // SCRAM-SHA-256: send AuthenticationSASL with mechanism list
            send(WireWriter::auth_sasl({"SCRAM-SHA-256"}));
            state_ = State::WAIT_SASL_INITIAL;
        } else {
            // Cleartext password fallback
            send(WireWriter::auth_cleartext());
            state_ = State::WAIT_PASSWORD;
        }
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

void WireSession::handle_sasl_initial(const WireFrame& frame) {
    // Client sends 'p' (password message) with SASLInitialResponse:
    //   mechanism_name\0  (null-terminated string)
    //   int32 length_of_initial_response (-1 if none)
    //   initial_response_data
    if (frame.type != wire::MSG_PASSWORD) {
        send_error("Expected SASL initial response");
        state_ = State::CLOSED;
        return;
    }

    // Parse mechanism name (null-terminated)
    const auto mechanism = WireBuffer::read_string(
        frame.payload.data(), frame.payload.size());
    if (mechanism != "SCRAM-SHA-256") {
        send_error("Unsupported SASL mechanism: " + mechanism, "28000");
        state_ = State::CLOSED;
        return;
    }

    // Skip mechanism name + null byte
    const size_t mech_len = mechanism.size() + 1;
    if (frame.payload.size() < mech_len + 4) {
        send_error("Invalid SASL initial response");
        state_ = State::CLOSED;
        return;
    }

    // Read initial response length
    const int32_t resp_len = WireBuffer::read_int32(
        frame.payload.data() + mech_len);

    if (resp_len <= 0 || mech_len + 4 + static_cast<size_t>(resp_len) > frame.payload.size()) {
        send_error("Invalid SASL initial response length");
        state_ = State::CLOSED;
        return;
    }

    // Parse client-first-message
    const std::string client_first(
        reinterpret_cast<const char*>(frame.payload.data() + mech_len + 4),
        static_cast<size_t>(resp_len));

    const auto parsed = ScramSha256::parse_client_first(client_first);
    if (!parsed.valid) {
        send_error("Invalid SCRAM client-first-message", "28000");
        state_ = State::CLOSED;
        return;
    }

    // Verify username matches the one from startup
    if (parsed.username != user_) {
        send_error("SCRAM username mismatch", "28P01");
        state_ = State::CLOSED;
        return;
    }

    // Save client-first-bare for auth message computation
    scram_client_first_bare_ = parsed.client_first_bare;

    // Generate server nonce and salt
    const std::string server_nonce = ScramSha256::generate_nonce();
    scram_combined_nonce_ = parsed.client_nonce + server_nonce;
    scram_salt_ = ScramSha256::generate_salt(16);

    // Pre-compute keys from the stored password
    const auto salted_pw = ScramSha256::salted_password(
        expected_password_, scram_salt_, scram_iterations_);
    scram_client_key_ = ScramSha256::client_key(salted_pw);
    scram_stored_key_ = ScramSha256::stored_key(scram_client_key_);
    scram_server_key_ = ScramSha256::server_key(salted_pw);

    // Build server-first-message: r=<combined_nonce>,s=<salt_b64>,i=<iterations>
    const std::string salt_b64 = ScramSha256::base64_encode(scram_salt_);
    scram_server_first_ = "r=" + scram_combined_nonce_ +
                          ",s=" + salt_b64 +
                          ",i=" + std::to_string(scram_iterations_);

    // Send AuthenticationSASLContinue
    send(WireWriter::auth_sasl_continue(scram_server_first_));
    state_ = State::WAIT_SASL_RESPONSE;
}

void WireSession::handle_sasl_response(const WireFrame& frame) {
    // Client sends 'p' (password message) with client-final-message
    if (frame.type != wire::MSG_PASSWORD) {
        send_error("Expected SASL response");
        state_ = State::CLOSED;
        return;
    }

    const std::string client_final(
        reinterpret_cast<const char*>(frame.payload.data()),
        frame.payload.size());

    const auto parsed = ScramSha256::parse_client_final(client_final);
    if (!parsed.valid) {
        send_error("Invalid SCRAM client-final-message", "28000");
        state_ = State::CLOSED;
        return;
    }

    // Verify nonce matches
    if (parsed.nonce != scram_combined_nonce_) {
        send_error("SCRAM nonce mismatch", "28P01");
        state_ = State::CLOSED;
        return;
    }

    // Build auth message: client-first-bare + "," + server-first + "," + client-final-without-proof
    const std::string auth_message =
        scram_client_first_bare_ + "," +
        scram_server_first_ + "," +
        parsed.without_proof;

    // Decode client proof
    const auto client_proof = ScramSha256::base64_decode(parsed.proof);

    // Verify client proof
    if (!ScramSha256::verify_client_proof(
            scram_stored_key_, auth_message, client_proof)) {
        send_error("SCRAM authentication failed", "28P01");
        state_ = State::CLOSED;
        return;
    }

    // Compute server signature
    const auto srv_sig = ScramSha256::server_signature(scram_server_key_, auth_message);
    const std::string server_final = "v=" + ScramSha256::base64_encode(srv_sig);

    // Send AuthenticationSASLFinal + AuthenticationOk
    send(WireWriter::auth_sasl_final(server_final));
    send(WireWriter::auth_ok());
    send(WireWriter::parameter_status("server_version", "15.0 (SQL Proxy)"));
    send(WireWriter::parameter_status("server_encoding", "UTF8"));
    send(WireWriter::parameter_status("client_encoding", "UTF8"));
    send(WireWriter::parameter_status("DateStyle", "ISO, MDY"));
    send(WireWriter::backend_key_data(static_cast<int32_t>(getpid()), 0));
    send(WireWriter::ready_for_query());
    state_ = State::READY;

    // Clear sensitive SCRAM state
    scram_stored_key_.clear();
    scram_server_key_.clear();
    scram_client_key_.clear();

    utils::log::info(std::format("Wire: {} authenticated via SCRAM-SHA-256 as {} to {}{}",
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
