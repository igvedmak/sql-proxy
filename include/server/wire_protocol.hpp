#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <optional>
#include <stdexcept>

namespace sqlproxy {

// PostgreSQL wire protocol v3 message types
namespace wire {

// Frontend (client → proxy)
constexpr char MSG_QUERY = 'Q';
constexpr char MSG_PARSE = 'P';
constexpr char MSG_BIND = 'B';
constexpr char MSG_EXECUTE = 'E';
constexpr char MSG_SYNC = 'S';
constexpr char MSG_TERMINATE = 'X';
constexpr char MSG_PASSWORD = 'p';

// Backend (proxy → client)
constexpr char MSG_AUTH = 'R';
constexpr char MSG_PARAM_STATUS = 'S';
constexpr char MSG_BACKEND_KEY = 'K';
constexpr char MSG_READY = 'Z';
constexpr char MSG_ROW_DESC = 'T';
constexpr char MSG_DATA_ROW = 'D';
constexpr char MSG_CMD_COMPLETE = 'C';
constexpr char MSG_ERROR = 'E';
constexpr char MSG_NOTICE = 'N';
constexpr char MSG_EMPTY_QUERY = 'I';

// Auth subtypes
constexpr int32_t AUTH_OK = 0;
constexpr int32_t AUTH_CLEARTEXT = 3;
constexpr int32_t AUTH_MD5 = 5;
constexpr int32_t AUTH_SASL = 10;
constexpr int32_t AUTH_SASL_CONTINUE = 11;
constexpr int32_t AUTH_SASL_FINAL = 12;

// Transaction states
constexpr char TX_IDLE = 'I';
constexpr char TX_IN_TRANSACTION = 'T';
constexpr char TX_ERROR = 'E';

// Error/Notice field types
constexpr char ERR_SEVERITY = 'S';
constexpr char ERR_SQLSTATE = 'C';
constexpr char ERR_MESSAGE = 'M';
constexpr char ERR_DETAIL = 'D';
constexpr char ERR_HINT = 'H';

// Startup message protocol version (3.0)
constexpr int32_t PROTOCOL_VERSION = 196608; // (3 << 16) | 0

} // namespace wire

// Raw frame read from the wire
struct WireFrame {
    char type;              // Message type byte (0 for startup message)
    std::vector<uint8_t> payload;

    WireFrame() : type(0) {}
    WireFrame(char t, std::vector<uint8_t> p) : type(t), payload(std::move(p)) {}
};

// Parsed startup message parameters
struct StartupMessage {
    int32_t protocol_version;
    std::string user;
    std::string database;
    std::unordered_map<std::string, std::string> params;
};

// Buffer for building wire protocol messages
class WireBuffer {
public:
    WireBuffer() { data_.reserve(256); }

    void clear() { data_.clear(); }

    // Write raw bytes
    void write_byte(uint8_t b);
    void write_int16(int16_t val);
    void write_int32(int32_t val);
    void write_string(std::string_view s);  // null-terminated
    void write_bytes(const uint8_t* data, size_t len);

    // Read helpers (for parsing incoming frames)
    [[nodiscard]] static int32_t read_int32(const uint8_t* data);
    [[nodiscard]] static int16_t read_int16(const uint8_t* data);
    [[nodiscard]] static std::string read_string(const uint8_t* data, size_t max_len);

    [[nodiscard]] const std::vector<uint8_t>& data() const { return data_; }
    [[nodiscard]] size_t size() const { return data_.size(); }

private:
    std::vector<uint8_t> data_;
};

// Writer for constructing complete wire protocol messages
class WireWriter {
public:
    // Build AuthenticationOk message
    [[nodiscard]] static std::vector<uint8_t> auth_ok();

    // Build AuthenticationCleartextPassword request
    [[nodiscard]] static std::vector<uint8_t> auth_cleartext();

    // Build AuthenticationSASL message (list of mechanism names)
    [[nodiscard]] static std::vector<uint8_t> auth_sasl(
        const std::vector<std::string>& mechanisms);

    // Build AuthenticationSASLContinue message (server challenge)
    [[nodiscard]] static std::vector<uint8_t> auth_sasl_continue(std::string_view data);

    // Build AuthenticationSASLFinal message (server signature)
    [[nodiscard]] static std::vector<uint8_t> auth_sasl_final(std::string_view data);

    // Build ParameterStatus message (key=value)
    [[nodiscard]] static std::vector<uint8_t> parameter_status(
        std::string_view key, std::string_view value);

    // Build BackendKeyData message
    [[nodiscard]] static std::vector<uint8_t> backend_key_data(int32_t pid, int32_t secret);

    // Build ReadyForQuery message
    [[nodiscard]] static std::vector<uint8_t> ready_for_query(char tx_state = wire::TX_IDLE);

    // Build RowDescription from column names
    [[nodiscard]] static std::vector<uint8_t> row_description(
        const std::vector<std::string>& columns,
        const std::vector<uint32_t>& type_oids = {});

    // Build DataRow from string values
    [[nodiscard]] static std::vector<uint8_t> data_row(
        const std::vector<std::string>& values);

    // Build CommandComplete message
    [[nodiscard]] static std::vector<uint8_t> command_complete(std::string_view tag);

    // Build ErrorResponse message
    [[nodiscard]] static std::vector<uint8_t> error_response(
        std::string_view severity, std::string_view sqlstate,
        std::string_view message, std::string_view detail = "");

    // Build EmptyQueryResponse
    [[nodiscard]] static std::vector<uint8_t> empty_query_response();

private:
    // Helper: build message with type byte + length prefix
    [[nodiscard]] static std::vector<uint8_t> build_message(char type, const WireBuffer& body);
};

// Parse a startup message from raw bytes
[[nodiscard]] std::optional<StartupMessage> parse_startup_message(const std::vector<uint8_t>& data);

// Parse a Query message (extract SQL string)
[[nodiscard]] std::string parse_query_message(const WireFrame& frame);

} // namespace sqlproxy
