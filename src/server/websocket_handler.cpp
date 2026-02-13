#include "server/websocket_handler.hpp"
#include "core/base64.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <cstring>
#include <format>

namespace sqlproxy {

// RFC 6455 magic GUID
static constexpr const char* WS_MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// ============================================================================
// Construction
// ============================================================================

WebSocketHandler::WebSocketHandler() = default;

WebSocketHandler::WebSocketHandler(Config config)
    : config_(std::move(config)) {}

// ============================================================================
// RFC 6455 Handshake
// ============================================================================

std::string WebSocketHandler::compute_accept_key(const std::string& client_key) {
    const std::string combined = client_key + WS_MAGIC_GUID;

    unsigned char hash[20]; // SHA1 = 20 bytes
    unsigned int hash_len = 0;

    EVP_Digest(
        combined.data(), combined.size(),
        hash, &hash_len,
        EVP_sha1(), nullptr);

    return base64::encode(hash, hash_len);
}

bool WebSocketHandler::is_upgrade_request(
    const std::string& upgrade_header,
    const std::string& connection_header) {
    // Case-insensitive check for "websocket" in Upgrade header
    std::string upgrade_lower = upgrade_header;
    std::transform(upgrade_lower.begin(), upgrade_lower.end(),
                   upgrade_lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    std::string connection_lower = connection_header;
    std::transform(connection_lower.begin(), connection_lower.end(),
                   connection_lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    return upgrade_lower == "websocket" &&
           connection_lower.find("upgrade") != std::string::npos;
}

std::string WebSocketHandler::build_upgrade_response(
    const std::string& accept_key) {
    return std::format(
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: {}\r\n"
        "\r\n", accept_key);
}

// ============================================================================
// Frame Encoding (server → client: unmasked)
// ============================================================================

std::vector<uint8_t> WebSocketHandler::encode_frame(
    WsOpcode opcode, const std::string& payload) {
    std::vector<uint8_t> frame;
    const size_t payload_len = payload.size();

    // FIN bit + opcode
    frame.push_back(0x80 | static_cast<uint8_t>(opcode));

    // Payload length (server frames are NOT masked)
    if (payload_len <= 125) {
        frame.push_back(static_cast<uint8_t>(payload_len));
    } else if (payload_len <= 65535) {
        frame.push_back(126);
        frame.push_back(static_cast<uint8_t>((payload_len >> 8) & 0xFF));
        frame.push_back(static_cast<uint8_t>(payload_len & 0xFF));
    } else {
        frame.push_back(127);
        for (int i = 7; i >= 0; --i) {
            frame.push_back(static_cast<uint8_t>(
                (payload_len >> (i * 8)) & 0xFF));
        }
    }

    // Payload
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

// ============================================================================
// Frame Decoding (client → server: masked per RFC 6455)
// ============================================================================

std::optional<WsFrame> WebSocketHandler::decode_frame(
    const uint8_t* data, size_t len, size_t& bytes_consumed) {
    bytes_consumed = 0;

    if (len < 2) return std::nullopt;

    size_t pos = 0;

    // Byte 0: FIN + RSV + Opcode
    const bool fin = (data[0] & 0x80) != 0;
    const auto opcode = static_cast<WsOpcode>(data[0] & 0x0F);
    ++pos;

    // Byte 1: MASK + Payload length
    const bool masked = (data[1] & 0x80) != 0;
    uint64_t payload_len = data[1] & 0x7F;
    ++pos;

    // Extended payload length
    if (payload_len == 126) {
        if (len < pos + 2) return std::nullopt;
        payload_len = (static_cast<uint64_t>(data[pos]) << 8) |
                       static_cast<uint64_t>(data[pos + 1]);
        pos += 2;
    } else if (payload_len == 127) {
        if (len < pos + 8) return std::nullopt;
        payload_len = 0;
        for (int i = 0; i < 8; ++i) {
            payload_len = (payload_len << 8) | static_cast<uint64_t>(data[pos + i]);
        }
        pos += 8;
    }

    // Masking key (4 bytes if masked)
    uint8_t mask_key[4] = {0};
    if (masked) {
        if (len < pos + 4) return std::nullopt;
        std::memcpy(mask_key, data + pos, 4);
        pos += 4;
    }

    // Payload data
    if (len < pos + payload_len) return std::nullopt;

    WsFrame frame;
    frame.fin = fin;
    frame.opcode = opcode;
    frame.payload.resize(static_cast<size_t>(payload_len));

    if (masked) {
        for (size_t i = 0; i < payload_len; ++i) {
            frame.payload[i] = data[pos + i] ^ mask_key[i % 4];
        }
    } else {
        std::memcpy(frame.payload.data(), data + pos, static_cast<size_t>(payload_len));
    }

    bytes_consumed = pos + static_cast<size_t>(payload_len);
    return frame;
}

// ============================================================================
// Stats & Connection Tracking
// ============================================================================

WebSocketHandler::Stats WebSocketHandler::get_stats() const {
    return {
        connections_total_.load(std::memory_order_relaxed),
        active_connections_.load(std::memory_order_relaxed),
        messages_sent_.load(std::memory_order_relaxed),
        messages_received_.load(std::memory_order_relaxed),
        frames_encoded_.load(std::memory_order_relaxed),
        frames_decoded_.load(std::memory_order_relaxed)
    };
}

void WebSocketHandler::increment_connection() {
    connections_total_.fetch_add(1, std::memory_order_relaxed);
    active_connections_.fetch_add(1, std::memory_order_relaxed);
}

void WebSocketHandler::decrement_connection() {
    active_connections_.fetch_sub(1, std::memory_order_relaxed);
}

void WebSocketHandler::increment_messages_sent() {
    messages_sent_.fetch_add(1, std::memory_order_relaxed);
}

void WebSocketHandler::increment_messages_received() {
    messages_received_.fetch_add(1, std::memory_order_relaxed);
}

} // namespace sqlproxy
