#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sqlproxy::base64 {

inline std::string encode(const uint8_t* data, size_t len) {
    static const char kChars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    result.reserve(4 * ((len + 2) / 3));

    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);

        result += kChars[(n >> 18) & 0x3F];
        result += kChars[(n >> 12) & 0x3F];
        result += (i + 1 < len) ? kChars[(n >> 6) & 0x3F] : '=';
        result += (i + 2 < len) ? kChars[n & 0x3F] : '=';
    }
    return result;
}

inline std::vector<uint8_t> decode(const std::string& encoded) {
    static const uint8_t kTable[128] = {
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,62,64,64,64,63,
        52,53,54,55,56,57,58,59,60,61,64,64,64,64,64,64,
        64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,64,64,64,64,64,
        64,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,64,64,64,64,64
    };

    std::vector<uint8_t> result;
    result.reserve(3 * encoded.size() / 4);

    uint32_t buf = 0;
    int bits = 0;
    for (const char c : encoded) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        if (static_cast<unsigned char>(c) >= 128) continue;
        uint8_t val = kTable[static_cast<unsigned char>(c)];
        if (val == 64) continue;

        buf = (buf << 6) | val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            result.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
        }
    }
    return result;
}

} // namespace sqlproxy::base64
