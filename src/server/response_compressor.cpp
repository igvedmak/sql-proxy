#include "server/response_compressor.hpp"

#include <zlib.h>

namespace sqlproxy {

ResponseCompressor::ResponseCompressor() = default;

ResponseCompressor::ResponseCompressor(const Config& config)
    : config_(config) {}

std::optional<std::string> ResponseCompressor::try_compress(std::string_view data) const {
    if (!config_.enabled || data.size() < config_.min_size_bytes) {
        return std::nullopt;
    }

    z_stream zs{};
    // windowBits=15+16 for gzip format
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                     15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return std::nullopt;
    }

    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data.data()));
    zs.avail_in = static_cast<uInt>(data.size());

    std::string compressed;
    compressed.resize(deflateBound(&zs, static_cast<uLong>(data.size())));

    zs.next_out = reinterpret_cast<Bytef*>(compressed.data());
    zs.avail_out = static_cast<uInt>(compressed.size());

    int ret = deflate(&zs, Z_FINISH);
    deflateEnd(&zs);

    if (ret != Z_STREAM_END) {
        return std::nullopt;
    }

    compressed.resize(zs.total_out);

    // Only use compressed if it's actually smaller
    if (compressed.size() >= data.size()) {
        return std::nullopt;
    }

    return compressed;
}

} // namespace sqlproxy
