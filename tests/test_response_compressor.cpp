#include <catch2/catch_test_macros.hpp>
#include "server/response_compressor.hpp"
#include "config/config_loader.hpp"

#include <zlib.h>
#include <string>

using namespace sqlproxy;

// Helper: decompress gzip data for verification (loop-based for any compression ratio)
static std::string gzip_decompress(const std::string& compressed) {
    z_stream zs{};
    if (inflateInit2(&zs, 15 + 16) != Z_OK) return "";

    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(compressed.data()));
    zs.avail_in = static_cast<uInt>(compressed.size());

    std::string output;
    const size_t chunk = 16384;
    int ret;
    do {
        size_t old_size = output.size();
        output.resize(old_size + chunk);
        zs.next_out = reinterpret_cast<Bytef*>(output.data() + old_size);
        zs.avail_out = static_cast<uInt>(chunk);
        ret = inflate(&zs, Z_NO_FLUSH);
    } while (ret == Z_OK);

    inflateEnd(&zs);
    if (ret != Z_STREAM_END) return "";
    output.resize(zs.total_out);
    return output;
}

TEST_CASE("ResponseCompressor: disabled returns nullopt", "[compression]") {
    ResponseCompressor::Config cfg;
    cfg.enabled = false;
    ResponseCompressor compressor(cfg);

    std::string data(2000, 'x');
    CHECK_FALSE(compressor.try_compress(data).has_value());
    CHECK_FALSE(compressor.should_compress(data.size()));
}

TEST_CASE("ResponseCompressor: small body not compressed", "[compression]") {
    ResponseCompressor::Config cfg;
    cfg.enabled = true;
    cfg.min_size_bytes = 1024;
    ResponseCompressor compressor(cfg);

    std::string small_data(512, 'x');
    CHECK_FALSE(compressor.should_compress(small_data.size()));
    CHECK_FALSE(compressor.try_compress(small_data).has_value());
}

TEST_CASE("ResponseCompressor: large body compressed + valid gzip", "[compression]") {
    ResponseCompressor::Config cfg;
    cfg.enabled = true;
    cfg.min_size_bytes = 100;
    ResponseCompressor compressor(cfg);

    // Create compressible data (repetitive JSON-like content)
    std::string data;
    for (int i = 0; i < 100; ++i) {
        data += R"({"id":)" + std::to_string(i) + R"(,"name":"test_user","role":"analyst"},)";
    }

    auto compressed = compressor.try_compress(data);
    REQUIRE(compressed.has_value());

    // Verify it decompresses back to original
    auto decompressed = gzip_decompress(*compressed);
    CHECK(decompressed == data);
}

TEST_CASE("ResponseCompressor: compressed is smaller than original", "[compression]") {
    ResponseCompressor::Config cfg;
    cfg.enabled = true;
    cfg.min_size_bytes = 100;
    ResponseCompressor compressor(cfg);

    // Highly compressible data
    std::string data(5000, 'A');
    auto compressed = compressor.try_compress(data);
    REQUIRE(compressed.has_value());
    CHECK(compressed->size() < data.size());
}

TEST_CASE("ResponseCompressor: empty input returns nullopt", "[compression]") {
    ResponseCompressor::Config cfg;
    cfg.enabled = true;
    cfg.min_size_bytes = 0;
    ResponseCompressor compressor(cfg);

    CHECK_FALSE(compressor.try_compress("").has_value());
}

TEST_CASE("ResponseCompressor: should_compress threshold check", "[compression]") {
    ResponseCompressor::Config cfg;
    cfg.enabled = true;
    cfg.min_size_bytes = 1024;
    ResponseCompressor compressor(cfg);

    CHECK_FALSE(compressor.should_compress(0));
    CHECK_FALSE(compressor.should_compress(1023));
    CHECK(compressor.should_compress(1024));
    CHECK(compressor.should_compress(2048));
}

TEST_CASE("ResponseCompressor: config from TOML", "[compression][config]") {
    std::string toml = R"(
[server]
compression_enabled = true
compression_min_size_bytes = 2048
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    REQUIRE(result.config.server.compression_enabled == true);
    REQUIRE(result.config.server.compression_min_size_bytes == 2048);
}
