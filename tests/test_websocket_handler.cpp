#include <catch2/catch_test_macros.hpp>
#include "server/websocket_handler.hpp"
#include <cstring>

using namespace sqlproxy;

TEST_CASE("WebSocketHandler", "[websocket]") {

    SECTION("Disabled by default") {
        WebSocketHandler handler;
        REQUIRE_FALSE(handler.is_enabled());
    }

    SECTION("Enabled with config") {
        WebSocketHandler::Config cfg;
        cfg.enabled = true;
        cfg.endpoint = "/ws";
        WebSocketHandler handler(cfg);
        REQUIRE(handler.is_enabled());
    }

    SECTION("Compute accept key matches RFC 6455 test vector") {
        // RFC 6455 Section 4.2.2 specifies this exact test vector:
        // Client key: "dGhlIHNhbXBsZSBub25jZQ=="
        // Expected:   "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        const std::string client_key = "dGhlIHNhbXBsZSBub25jZQ==";
        const std::string expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

        auto result = WebSocketHandler::compute_accept_key(client_key);
        REQUIRE(result == expected);
    }

    SECTION("Encode text frame - small payload") {
        const std::string payload = "Hello";
        auto frame = WebSocketHandler::encode_frame(WsOpcode::TEXT, payload);

        // Byte 0: FIN=1 + TEXT opcode (0x81)
        REQUIRE(frame[0] == 0x81);
        // Byte 1: length=5, no mask (0x05)
        REQUIRE(frame[1] == 0x05);
        // Payload
        REQUIRE(frame.size() == 2 + 5);
        REQUIRE(std::string(frame.begin() + 2, frame.end()) == "Hello");
    }

    SECTION("Encode text frame - 16-bit length") {
        // Create payload > 125 bytes
        const std::string payload(200, 'X');
        auto frame = WebSocketHandler::encode_frame(WsOpcode::TEXT, payload);

        // Byte 0: FIN=1 + TEXT opcode (0x81)
        REQUIRE(frame[0] == 0x81);
        // Byte 1: extended length marker (126)
        REQUIRE(frame[1] == 126);
        // Bytes 2-3: 16-bit length (big-endian) = 200
        REQUIRE(frame[2] == 0x00);
        REQUIRE(frame[3] == 200);
        // Total: 2 + 2 + 200 = 204 bytes
        REQUIRE(frame.size() == 204);
    }

    SECTION("Encode close frame") {
        auto frame = WebSocketHandler::encode_frame(WsOpcode::CLOSE, "");
        REQUIRE(frame[0] == 0x88);  // FIN + CLOSE
        REQUIRE(frame[1] == 0x00);  // length 0
        REQUIRE(frame.size() == 2);
    }

    SECTION("Decode masked frame (client → server)") {
        // Build a masked text frame: "Hello"
        std::vector<uint8_t> raw;
        raw.push_back(0x81);  // FIN + TEXT
        raw.push_back(0x85);  // MASK=1, length=5

        // Masking key
        uint8_t mask[4] = {0x37, 0xFA, 0x21, 0x3D};
        raw.insert(raw.end(), mask, mask + 4);

        // Masked payload
        const char* hello = "Hello";
        for (int i = 0; i < 5; ++i) {
            raw.push_back(static_cast<uint8_t>(hello[i]) ^ mask[i % 4]);
        }

        size_t consumed = 0;
        auto frame = WebSocketHandler::decode_frame(raw.data(), raw.size(), consumed);

        REQUIRE(frame.has_value());
        REQUIRE(frame->fin == true);
        REQUIRE(frame->opcode == WsOpcode::TEXT);
        REQUIRE(frame->payload.size() == 5);
        REQUIRE(std::string(frame->payload.begin(), frame->payload.end()) == "Hello");
        REQUIRE(consumed == raw.size());
    }

    SECTION("Decode unmasked frame (server → server)") {
        // Build an unmasked text frame: "Test"
        std::vector<uint8_t> raw;
        raw.push_back(0x81);  // FIN + TEXT
        raw.push_back(0x04);  // no mask, length=4
        raw.push_back('T');
        raw.push_back('e');
        raw.push_back('s');
        raw.push_back('t');

        size_t consumed = 0;
        auto frame = WebSocketHandler::decode_frame(raw.data(), raw.size(), consumed);

        REQUIRE(frame.has_value());
        REQUIRE(frame->fin == true);
        REQUIRE(frame->opcode == WsOpcode::TEXT);
        REQUIRE(std::string(frame->payload.begin(), frame->payload.end()) == "Test");
        REQUIRE(consumed == 6);
    }

    SECTION("Decode returns nullopt for incomplete frame") {
        // Only 1 byte — not enough
        std::vector<uint8_t> raw = {0x81};
        size_t consumed = 0;
        auto frame = WebSocketHandler::decode_frame(raw.data(), raw.size(), consumed);
        REQUIRE_FALSE(frame.has_value());
        REQUIRE(consumed == 0);
    }

    SECTION("Is upgrade request") {
        REQUIRE(WebSocketHandler::is_upgrade_request("websocket", "Upgrade"));
        REQUIRE(WebSocketHandler::is_upgrade_request("WebSocket", "Upgrade, keep-alive"));
        REQUIRE_FALSE(WebSocketHandler::is_upgrade_request("http", "Upgrade"));
        REQUIRE_FALSE(WebSocketHandler::is_upgrade_request("websocket", "close"));
    }

    SECTION("Build upgrade response") {
        const auto response = WebSocketHandler::build_upgrade_response("abc123");
        REQUIRE(response.find("101 Switching Protocols") != std::string::npos);
        REQUIRE(response.find("Sec-WebSocket-Accept: abc123") != std::string::npos);
        REQUIRE(response.find("Upgrade: websocket") != std::string::npos);
    }

    SECTION("Stats tracking") {
        WebSocketHandler handler;

        handler.increment_connection();
        handler.increment_connection();
        handler.decrement_connection();
        handler.increment_messages_sent();
        handler.increment_messages_sent();
        handler.increment_messages_sent();
        handler.increment_messages_received();

        auto stats = handler.get_stats();
        REQUIRE(stats.connections_total == 2);
        REQUIRE(stats.active_connections == 1);
        REQUIRE(stats.messages_sent == 3);
        REQUIRE(stats.messages_received == 1);
    }
}
