#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace sqlproxy {

class ResponseCompressor {
public:
    struct Config {
        bool enabled = false;
        size_t min_size_bytes = 1024;  // Only compress above this threshold
    };

    ResponseCompressor();
    explicit ResponseCompressor(const Config& config);

    /// Returns compressed data if beneficial, nullopt otherwise.
    /// Caller should set Content-Encoding: gzip when this returns a value.
    [[nodiscard]] std::optional<std::string> try_compress(std::string_view data) const;

    [[nodiscard]] bool is_enabled() const { return config_.enabled; }

    [[nodiscard]] bool should_compress(size_t body_size) const {
        return config_.enabled && body_size >= config_.min_size_bytes;
    }

private:
    Config config_;
};

} // namespace sqlproxy
