#include "server/wire_copy.hpp"
#include "server/wire_protocol.hpp"

#include <algorithm>
#include <cctype>

namespace sqlproxy {

namespace copy {

namespace {

// Case-insensitive string prefix check
bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

// Skip whitespace starting at pos, return new position
size_t skip_ws(const std::string& s, size_t pos) {
    while (pos < s.size() && std::isspace(static_cast<unsigned char>(s[pos]))) ++pos;
    return pos;
}

// Read a word (non-whitespace token), return it and advance pos
std::string read_word(const std::string& s, size_t& pos) {
    pos = skip_ws(s, pos);
    const size_t start = pos;
    while (pos < s.size() && !std::isspace(static_cast<unsigned char>(s[pos])) &&
           s[pos] != '(' && s[pos] != ')' && s[pos] != ';') {
        ++pos;
    }
    return s.substr(start, pos - start);
}

} // anonymous namespace

std::optional<CopyStatement> parse_copy_statement(const std::string& sql) {
    size_t pos = 0;

    // First word must be "COPY"
    const std::string first = read_word(sql, pos);
    if (!iequals(first, "COPY")) return std::nullopt;

    // Table name
    const std::string table = read_word(sql, pos);
    if (table.empty()) return std::nullopt;

    // Optional column list in parentheses — skip it
    pos = skip_ws(sql, pos);
    if (pos < sql.size() && sql[pos] == '(') {
        const auto close = sql.find(')', pos);
        if (close == std::string::npos) return std::nullopt;
        pos = close + 1;
    }

    // Direction: FROM or TO
    std::string direction_word = read_word(sql, pos);

    CopyStatement stmt;
    stmt.table_name = table;
    stmt.format = 0;

    if (iequals(direction_word, "FROM")) {
        const std::string source = read_word(sql, pos);
        if (iequals(source, "STDIN") || iequals(source, "stdin")) {
            stmt.direction = CopyStatement::FROM_STDIN;
        } else {
            stmt.direction = CopyStatement::FROM_FILE;
        }
    } else if (iequals(direction_word, "TO")) {
        const std::string dest = read_word(sql, pos);
        if (iequals(dest, "STDOUT") || iequals(dest, "stdout")) {
            stmt.direction = CopyStatement::TO_STDOUT;
        } else {
            stmt.direction = CopyStatement::TO_FILE;
        }
    } else {
        return std::nullopt;
    }

    // Check for WITH options (FORMAT)
    pos = skip_ws(sql, pos);
    while (pos < sql.size()) {
        const std::string opt = read_word(sql, pos);
        if (opt.empty()) break;
        if (iequals(opt, "WITH") || iequals(opt, "(")) continue;
        if (iequals(opt, "FORMAT")) {
            std::string fmt = read_word(sql, pos);
            if (iequals(fmt, "BINARY") || iequals(fmt, "binary")) {
                stmt.format = 1;
            }
        }
        if (iequals(opt, "BINARY")) {
            stmt.format = 1;
        }
    }

    return stmt;
}

} // namespace copy

// ============================================================================
// WireCopyWriter
// ============================================================================

std::vector<uint8_t> WireCopyWriter::copy_in_response(int8_t format, int16_t num_columns) {
    WireBuffer buf;
    buf.write_byte(static_cast<uint8_t>(format));
    buf.write_int16(num_columns);
    for (int16_t i = 0; i < num_columns; ++i) {
        buf.write_int16(format);  // Per-column format code
    }

    // Build message: type byte + length + body
    std::vector<uint8_t> msg;
    const int32_t len = static_cast<int32_t>(buf.size() + 4);
    msg.reserve(1 + 4 + buf.size());
    msg.push_back(static_cast<uint8_t>(wire::MSG_COPY_IN_RESPONSE));
    msg.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
    msg.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
    msg.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    msg.push_back(static_cast<uint8_t>(len & 0xFF));
    msg.insert(msg.end(), buf.data().begin(), buf.data().end());
    return msg;
}

std::vector<uint8_t> WireCopyWriter::copy_out_response(int8_t format, int16_t num_columns) {
    WireBuffer buf;
    buf.write_byte(static_cast<uint8_t>(format));
    buf.write_int16(num_columns);
    for (int16_t i = 0; i < num_columns; ++i) {
        buf.write_int16(format);
    }

    std::vector<uint8_t> msg;
    const int32_t len = static_cast<int32_t>(buf.size() + 4);
    msg.reserve(1 + 4 + buf.size());
    msg.push_back(static_cast<uint8_t>(wire::MSG_COPY_OUT_RESPONSE));
    msg.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
    msg.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
    msg.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    msg.push_back(static_cast<uint8_t>(len & 0xFF));
    msg.insert(msg.end(), buf.data().begin(), buf.data().end());
    return msg;
}

std::vector<uint8_t> WireCopyWriter::copy_data(const uint8_t* data, size_t len) {
    std::vector<uint8_t> msg;
    const int32_t total_len = static_cast<int32_t>(len + 4);
    msg.reserve(1 + 4 + len);
    msg.push_back(static_cast<uint8_t>(wire::MSG_COPY_DATA));
    msg.push_back(static_cast<uint8_t>((total_len >> 24) & 0xFF));
    msg.push_back(static_cast<uint8_t>((total_len >> 16) & 0xFF));
    msg.push_back(static_cast<uint8_t>((total_len >> 8) & 0xFF));
    msg.push_back(static_cast<uint8_t>(total_len & 0xFF));
    msg.insert(msg.end(), data, data + len);
    return msg;
}

std::vector<uint8_t> WireCopyWriter::copy_data(const std::string& text) {
    return copy_data(reinterpret_cast<const uint8_t*>(text.data()), text.size());
}

std::vector<uint8_t> WireCopyWriter::copy_done() {
    std::vector<uint8_t> msg;
    msg.push_back(static_cast<uint8_t>(wire::MSG_COPY_DONE));
    // Length = 4 (just the length field itself)
    msg.push_back(0);
    msg.push_back(0);
    msg.push_back(0);
    msg.push_back(4);
    return msg;
}

std::vector<uint8_t> WireCopyWriter::copy_fail(const std::string& error_msg) {
    WireBuffer buf;
    buf.write_string(error_msg);

    std::vector<uint8_t> msg;
    const int32_t len = static_cast<int32_t>(buf.size() + 4);
    msg.reserve(1 + 4 + buf.size());
    msg.push_back(static_cast<uint8_t>(wire::MSG_COPY_FAIL));
    msg.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
    msg.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
    msg.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    msg.push_back(static_cast<uint8_t>(len & 0xFF));
    msg.insert(msg.end(), buf.data().begin(), buf.data().end());
    return msg;
}

} // namespace sqlproxy
