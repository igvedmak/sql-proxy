#include <catch2/catch_test_macros.hpp>
#include "server/wire_protocol.hpp"

using namespace sqlproxy;

// ============================================================================
// Wire protocol constants
// ============================================================================

TEST_CASE("Wire protocol: message type constants", "[wire]") {
    REQUIRE(wire::MSG_QUERY == 'Q');
    REQUIRE(wire::MSG_TERMINATE == 'X');
    REQUIRE(wire::MSG_AUTH == 'R');
    REQUIRE(wire::MSG_READY == 'Z');
    REQUIRE(wire::MSG_ROW_DESC == 'T');
    REQUIRE(wire::MSG_DATA_ROW == 'D');
    REQUIRE(wire::MSG_CMD_COMPLETE == 'C');
    REQUIRE(wire::MSG_ERROR == 'E');
    REQUIRE(wire::MSG_PASSWORD == 'p');
}

TEST_CASE("Wire protocol: auth subtypes", "[wire]") {
    REQUIRE(wire::AUTH_OK == 0);
    REQUIRE(wire::AUTH_CLEARTEXT == 3);
    REQUIRE(wire::AUTH_MD5 == 5);
}

TEST_CASE("Wire protocol: protocol version", "[wire]") {
    REQUIRE(wire::PROTOCOL_VERSION == 196608);
    REQUIRE(wire::PROTOCOL_VERSION == (3 << 16));
}

TEST_CASE("Wire protocol: transaction states", "[wire]") {
    REQUIRE(wire::TX_IDLE == 'I');
    REQUIRE(wire::TX_IN_TRANSACTION == 'T');
    REQUIRE(wire::TX_ERROR == 'E');
}

// ============================================================================
// WireBuffer
// ============================================================================

TEST_CASE("WireBuffer: write and read int32", "[wire]") {
    WireBuffer buf;

    buf.write_int32(0x01020304);
    REQUIRE(buf.size() == 4);

    auto data = buf.data();
    int32_t val = WireBuffer::read_int32(data.data());
    REQUIRE(val == 0x01020304);
}

TEST_CASE("WireBuffer: write and read int16", "[wire]") {
    WireBuffer buf;

    buf.write_int16(0x0102);
    REQUIRE(buf.size() == 2);

    auto data = buf.data();
    int16_t val = WireBuffer::read_int16(data.data());
    REQUIRE(val == 0x0102);
}

TEST_CASE("WireBuffer: write string (null-terminated)", "[wire]") {
    WireBuffer buf;
    buf.write_string("hello");
    REQUIRE(buf.size() == 6); // "hello" + null

    auto data = buf.data();
    std::string result = WireBuffer::read_string(data.data(), buf.size());
    REQUIRE(result == "hello");
}

TEST_CASE("WireBuffer: write byte", "[wire]") {
    WireBuffer buf;
    buf.write_byte(0xFF);
    REQUIRE(buf.size() == 1);
    REQUIRE(buf.data()[0] == 0xFF);
}

TEST_CASE("WireBuffer: clear resets buffer", "[wire]") {
    WireBuffer buf;
    buf.write_int32(42);
    REQUIRE(buf.size() == 4);
    buf.clear();
    REQUIRE(buf.size() == 0);
}

// ============================================================================
// WireWriter - message builders
// ============================================================================

TEST_CASE("WireWriter: auth_ok message", "[wire]") {
    auto msg = WireWriter::auth_ok();
    REQUIRE(!msg.empty());
    // Type byte should be 'R'
    REQUIRE(msg[0] == static_cast<uint8_t>(wire::MSG_AUTH));
}

TEST_CASE("WireWriter: auth_cleartext message", "[wire]") {
    auto msg = WireWriter::auth_cleartext();
    REQUIRE(!msg.empty());
    REQUIRE(msg[0] == static_cast<uint8_t>(wire::MSG_AUTH));
}

TEST_CASE("WireWriter: parameter_status message", "[wire]") {
    auto msg = WireWriter::parameter_status("server_version", "15.0");
    REQUIRE(!msg.empty());
    REQUIRE(msg[0] == static_cast<uint8_t>(wire::MSG_PARAM_STATUS));
}

TEST_CASE("WireWriter: backend_key_data message", "[wire]") {
    auto msg = WireWriter::backend_key_data(12345, 67890);
    REQUIRE(!msg.empty());
    REQUIRE(msg[0] == static_cast<uint8_t>(wire::MSG_BACKEND_KEY));
}

TEST_CASE("WireWriter: ready_for_query message", "[wire]") {
    auto msg = WireWriter::ready_for_query(wire::TX_IDLE);
    REQUIRE(!msg.empty());
    REQUIRE(msg[0] == static_cast<uint8_t>(wire::MSG_READY));
    // Last byte should be TX state
    REQUIRE(msg.back() == static_cast<uint8_t>(wire::TX_IDLE));
}

TEST_CASE("WireWriter: row_description message", "[wire]") {
    std::vector<std::string> columns = {"id", "name", "email"};
    auto msg = WireWriter::row_description(columns);
    REQUIRE(!msg.empty());
    REQUIRE(msg[0] == static_cast<uint8_t>(wire::MSG_ROW_DESC));
}

TEST_CASE("WireWriter: data_row message", "[wire]") {
    std::vector<std::string> values = {"1", "Alice", "alice@example.com"};
    auto msg = WireWriter::data_row(values);
    REQUIRE(!msg.empty());
    REQUIRE(msg[0] == static_cast<uint8_t>(wire::MSG_DATA_ROW));
}

TEST_CASE("WireWriter: command_complete message", "[wire]") {
    auto msg = WireWriter::command_complete("SELECT 5");
    REQUIRE(!msg.empty());
    REQUIRE(msg[0] == static_cast<uint8_t>(wire::MSG_CMD_COMPLETE));
}

TEST_CASE("WireWriter: error_response message", "[wire]") {
    auto msg = WireWriter::error_response("ERROR", "42000", "Syntax error", "near SELECT");
    REQUIRE(!msg.empty());
    REQUIRE(msg[0] == static_cast<uint8_t>(wire::MSG_ERROR));
}

TEST_CASE("WireWriter: empty_query_response message", "[wire]") {
    auto msg = WireWriter::empty_query_response();
    REQUIRE(!msg.empty());
    REQUIRE(msg[0] == static_cast<uint8_t>(wire::MSG_EMPTY_QUERY));
}

// ============================================================================
// Startup message parsing
// ============================================================================

TEST_CASE("Wire protocol: parse startup message", "[wire]") {
    // Build startup message payload (no length prefix — parser expects data starting at version)
    // [4-byte version][key\0value\0...key\0value\0\0]
    WireBuffer buf;
    buf.write_int32(wire::PROTOCOL_VERSION);
    buf.write_string("user");
    buf.write_string("testuser");
    buf.write_string("database");
    buf.write_string("testdb");
    buf.write_byte(0); // terminator

    auto data = buf.data();
    std::vector<uint8_t> msg(data.begin(), data.end());

    auto result = parse_startup_message(msg);
    REQUIRE(result.has_value());
    REQUIRE(result->protocol_version == wire::PROTOCOL_VERSION);
    REQUIRE(result->user == "testuser");
    REQUIRE(result->database == "testdb");
}

TEST_CASE("Wire protocol: parse startup message - empty data", "[wire]") {
    std::vector<uint8_t> empty;
    auto result = parse_startup_message(empty);
    REQUIRE_FALSE(result.has_value());
}

// ============================================================================
// Query message parsing
// ============================================================================

TEST_CASE("Wire protocol: parse query message", "[wire]") {
    // Query message payload is just the SQL string (null-terminated)
    std::string sql = "SELECT * FROM users";
    std::vector<uint8_t> payload(sql.begin(), sql.end());
    payload.push_back(0); // null terminator

    WireFrame frame(wire::MSG_QUERY, std::move(payload));
    std::string parsed = parse_query_message(frame);
    REQUIRE(parsed == sql);
}

TEST_CASE("Wire protocol: parse empty query message", "[wire]") {
    std::vector<uint8_t> payload = {0}; // just null terminator
    WireFrame frame(wire::MSG_QUERY, std::move(payload));
    std::string parsed = parse_query_message(frame);
    REQUIRE(parsed.empty());
}

// ============================================================================
// WireFrame
// ============================================================================

TEST_CASE("WireFrame: default construction", "[wire]") {
    WireFrame frame;
    REQUIRE(frame.type == 0);
    REQUIRE(frame.payload.empty());
}

TEST_CASE("WireFrame: parameterized construction", "[wire]") {
    std::vector<uint8_t> payload = {1, 2, 3};
    WireFrame frame('Q', payload);
    REQUIRE(frame.type == 'Q');
    REQUIRE(frame.payload.size() == 3);
}
