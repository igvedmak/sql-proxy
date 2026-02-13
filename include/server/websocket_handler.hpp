#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace sqlproxy {

class Pipeline;

// WebSocket frame opcodes per RFC 6455
enum class WsOpcode : uint8_t {
    CONTINUATION = 0x0,
    TEXT         = 0x1,
    BINARY       = 0x2,
    CLOSE        = 0x8,
    PING         = 0x9,
    PONG         = 0xA
};

// Decoded WebSocket frame
struct WsFrame {
    bool fin = true;
    WsOpcode opcode = WsOpcode::TEXT;
    std::vector<uint8_t> payload;
};

// Stream subscription types
enum class StreamType : uint8_t { AUDIT, METRICS, QUERY };

/**
 * @brief WebSocket handler implementing RFC 6455 protocol.
 *
 * Provides:
 * - HTTP upgrade handshake (SHA1 + base64)
 * - Frame encoding/decoding
 * - Stream subscriptions (audit, metrics, query)
 */
class WebSocketHandler {
public:
    struct Config {
        bool enabled = false;
        std::string endpoint = "/api/v1/stream";
        uint32_t max_connections = 100;
        uint32_t ping_interval_seconds = 30;
        size_t max_frame_size = 65536;
    };

    WebSocketHandler();
    explicit WebSocketHandler(Config config);

    [[nodiscard]] bool is_enabled() const { return config_.enabled; }

    // RFC 6455 handshake: SHA1(client_key + magic_guid) → base64
    [[nodiscard]] static std::string compute_accept_key(const std::string& client_key);

    // Frame encoding per RFC 6455 (server→client: unmasked)
    [[nodiscard]] static std::vector<uint8_t> encode_frame(
        WsOpcode opcode, const std::string& payload);

    // Frame decoding per RFC 6455 (client→server: masked)
    [[nodiscard]] static std::optional<WsFrame> decode_frame(
        const uint8_t* data, size_t len, size_t& bytes_consumed);

    // Validate WebSocket upgrade request headers
    [[nodiscard]] static bool is_upgrade_request(
        const std::string& upgrade_header,
        const std::string& connection_header);

    // Build HTTP 101 response headers
    [[nodiscard]] static std::string build_upgrade_response(
        const std::string& accept_key);

    struct Stats {
        uint64_t connections_total = 0;
        uint64_t active_connections = 0;
        uint64_t messages_sent = 0;
        uint64_t messages_received = 0;
        uint64_t frames_encoded = 0;
        uint64_t frames_decoded = 0;
    };

    [[nodiscard]] Stats get_stats() const;

    void increment_connection();
    void decrement_connection();
    void increment_messages_sent();
    void increment_messages_received();

private:
    Config config_;

    std::atomic<uint64_t> connections_total_{0};
    std::atomic<uint64_t> active_connections_{0};
    std::atomic<uint64_t> messages_sent_{0};
    std::atomic<uint64_t> messages_received_{0};
    std::atomic<uint64_t> frames_encoded_{0};
    std::atomic<uint64_t> frames_decoded_{0};
};

} // namespace sqlproxy
