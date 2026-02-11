#include "server/wire_protocol.hpp"

// GCC 14 false positive: -Wfree-nonheap-object in std::vector<uint8_t>::push_back
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfree-nonheap-object"
#endif

#include <cstring>

namespace sqlproxy {

// ============================================================================
// WireBuffer
// ============================================================================

void WireBuffer::write_byte(uint8_t b) {
    data_.push_back(b);
}

void WireBuffer::write_int16(int16_t val) {
    // Network byte order (big-endian)
    data_.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    data_.push_back(static_cast<uint8_t>(val & 0xFF));
}

void WireBuffer::write_int32(int32_t val) {
    data_.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
    data_.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    data_.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    data_.push_back(static_cast<uint8_t>(val & 0xFF));
}

void WireBuffer::write_string(std::string_view s) {
    data_.insert(data_.end(), s.begin(), s.end());
    data_.push_back(0);  // null terminator
}

void WireBuffer::write_bytes(const uint8_t* data, size_t len) {
    data_.insert(data_.end(), data, data + len);
}

int32_t WireBuffer::read_int32(const uint8_t* data) {
    return (static_cast<int32_t>(data[0]) << 24) |
           (static_cast<int32_t>(data[1]) << 16) |
           (static_cast<int32_t>(data[2]) << 8) |
           static_cast<int32_t>(data[3]);
}

int16_t WireBuffer::read_int16(const uint8_t* data) {
    return static_cast<int16_t>((static_cast<int16_t>(data[0]) << 8) |
                                 static_cast<int16_t>(data[1]));
}

std::string WireBuffer::read_string(const uint8_t* data, size_t max_len) {
    size_t len = 0;
    while (len < max_len && data[len] != 0) ++len;
    return std::string(reinterpret_cast<const char*>(data), len);
}

// ============================================================================
// WireWriter
// ============================================================================

std::vector<uint8_t> WireWriter::build_message(char type, const WireBuffer& body) {
    // Format: type(1) + length(4) + body
    // Length includes itself (4 bytes) but not the type byte
    int32_t length = static_cast<int32_t>(body.size() + 4);
    std::vector<uint8_t> msg;
    msg.reserve(1 + 4 + body.size());
    msg.push_back(static_cast<uint8_t>(type));
    msg.push_back(static_cast<uint8_t>((length >> 24) & 0xFF));
    msg.push_back(static_cast<uint8_t>((length >> 16) & 0xFF));
    msg.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
    msg.push_back(static_cast<uint8_t>(length & 0xFF));
    msg.insert(msg.end(), body.data().begin(), body.data().end());
    return msg;
}

std::vector<uint8_t> WireWriter::auth_ok() {
    WireBuffer body;
    body.write_int32(wire::AUTH_OK);
    return build_message(wire::MSG_AUTH, body);
}

std::vector<uint8_t> WireWriter::auth_cleartext() {
    WireBuffer body;
    body.write_int32(wire::AUTH_CLEARTEXT);
    return build_message(wire::MSG_AUTH, body);
}

std::vector<uint8_t> WireWriter::parameter_status(std::string_view key, std::string_view value) {
    WireBuffer body;
    body.write_string(key);
    body.write_string(value);
    return build_message(wire::MSG_PARAM_STATUS, body);
}

std::vector<uint8_t> WireWriter::backend_key_data(int32_t pid, int32_t secret) {
    WireBuffer body;
    body.write_int32(pid);
    body.write_int32(secret);
    return build_message(wire::MSG_BACKEND_KEY, body);
}

std::vector<uint8_t> WireWriter::ready_for_query(char tx_state) {
    WireBuffer body;
    body.write_byte(static_cast<uint8_t>(tx_state));
    return build_message(wire::MSG_READY, body);
}

std::vector<uint8_t> WireWriter::row_description(
    const std::vector<std::string>& columns,
    const std::vector<uint32_t>& type_oids) {
    WireBuffer body;
    body.write_int16(static_cast<int16_t>(columns.size()));

    for (size_t i = 0; i < columns.size(); ++i) {
        body.write_string(columns[i]);              // column name
        body.write_int32(0);                         // table OID
        body.write_int16(0);                         // column number
        const uint32_t type_oid = (i < type_oids.size()) ? type_oids[i] : 25;  // 25 = text
        body.write_int32(static_cast<int32_t>(type_oid));  // type OID
        body.write_int16(-1);                        // type size (-1 = variable)
        body.write_int32(-1);                        // type modifier
        body.write_int16(0);                         // format code (0 = text)
    }

    return build_message(wire::MSG_ROW_DESC, body);
}

std::vector<uint8_t> WireWriter::data_row(const std::vector<std::string>& values) {
    WireBuffer body;
    body.write_int16(static_cast<int16_t>(values.size()));

    for (const auto& val : values) {
        if (val == "NULL" || val.empty()) {
            body.write_int32(-1);  // NULL value
        } else {
            body.write_int32(static_cast<int32_t>(val.size()));
            body.write_bytes(reinterpret_cast<const uint8_t*>(val.data()), val.size());
        }
    }

    return build_message(wire::MSG_DATA_ROW, body);
}

std::vector<uint8_t> WireWriter::command_complete(std::string_view tag) {
    WireBuffer body;
    body.write_string(tag);
    return build_message(wire::MSG_CMD_COMPLETE, body);
}

std::vector<uint8_t> WireWriter::error_response(
    std::string_view severity, std::string_view sqlstate,
    std::string_view message, std::string_view detail) {
    WireBuffer body;

    body.write_byte(wire::ERR_SEVERITY);
    body.write_string(severity);

    body.write_byte(wire::ERR_SQLSTATE);
    body.write_string(sqlstate);

    body.write_byte(wire::ERR_MESSAGE);
    body.write_string(message);

    if (!detail.empty()) {
        body.write_byte(wire::ERR_DETAIL);
        body.write_string(detail);
    }

    body.write_byte(0);  // terminator

    return build_message(wire::MSG_ERROR, body);
}

std::vector<uint8_t> WireWriter::empty_query_response() {
    WireBuffer body;
    return build_message(wire::MSG_EMPTY_QUERY, body);
}

// ============================================================================
// Parsing functions
// ============================================================================

std::optional<StartupMessage> parse_startup_message(const std::vector<uint8_t>& data) {
    if (data.size() < 4) return std::nullopt;

    StartupMessage msg;
    msg.protocol_version = WireBuffer::read_int32(data.data());

    // Parse key=value pairs
    size_t pos = 4;  // Skip protocol version
    while (pos < data.size()) {
        const std::string key = WireBuffer::read_string(data.data() + pos, data.size() - pos);
        if (key.empty()) break;  // End of parameters
        pos += key.size() + 1;

        if (pos >= data.size()) break;
        std::string value = WireBuffer::read_string(data.data() + pos, data.size() - pos);
        pos += value.size() + 1;

        if (key == "user") {
            msg.user = value;
        } else if (key == "database") {
            msg.database = value;
        }
        msg.params[std::move(key)] = std::move(value);
    }

    return msg;
}

std::string parse_query_message(const WireFrame& frame) {
    if (frame.payload.empty()) return "";
    // Query message payload is just a null-terminated SQL string
    return WireBuffer::read_string(frame.payload.data(), frame.payload.size());
}

} // namespace sqlproxy

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
