#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sqlproxy {
namespace copy {

struct CopyStatement {
    enum Direction { FROM_STDIN, TO_STDOUT, FROM_FILE, TO_FILE };
    Direction direction;
    std::string table_name;
    int8_t format = 0;  // 0=text, 1=binary
};

// Parse a COPY statement from SQL text
[[nodiscard]] std::optional<CopyStatement> parse_copy_statement(const std::string& sql);

} // namespace copy

// Wire protocol COPY message constants
namespace wire {
    constexpr char MSG_COPY_IN_RESPONSE = 'G';
    constexpr char MSG_COPY_OUT_RESPONSE = 'H';
    constexpr char MSG_COPY_DATA = 'd';
    constexpr char MSG_COPY_DONE = 'c';
    constexpr char MSG_COPY_FAIL = 'f';
}

// WireWriter additions for COPY protocol
class WireCopyWriter {
public:
    [[nodiscard]] static std::vector<uint8_t> copy_in_response(int8_t format, int16_t num_columns);
    [[nodiscard]] static std::vector<uint8_t> copy_out_response(int8_t format, int16_t num_columns);
    [[nodiscard]] static std::vector<uint8_t> copy_data(const uint8_t* data, size_t len);
    [[nodiscard]] static std::vector<uint8_t> copy_data(const std::string& text);
    [[nodiscard]] static std::vector<uint8_t> copy_done();
    [[nodiscard]] static std::vector<uint8_t> copy_fail(const std::string& error_msg);
};

} // namespace sqlproxy
