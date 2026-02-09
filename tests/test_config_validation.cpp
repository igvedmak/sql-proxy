#include <catch2/catch_test_macros.hpp>
#include "config/config_loader.hpp"

using namespace sqlproxy;

TEST_CASE("ConfigValidation: invalid port 0 fails", "[config][validation]") {
    const std::string toml = R"(
[server]
port = 0
)";
    auto result = ConfigLoader::load_from_string(toml);
    CHECK_FALSE(result.success);
    CHECK(result.error_message.find("server.port") != std::string::npos);
}

TEST_CASE("ConfigValidation: circuit breaker zero threshold fails", "[config][validation]") {
    const std::string toml = R"(
[server]
port = 8080

[circuit_breaker]
enabled = true
failure_threshold = 0
timeout_ms = 5000
)";
    auto result = ConfigLoader::load_from_string(toml);
    CHECK_FALSE(result.success);
    CHECK(result.error_message.find("failure_threshold") != std::string::npos);
}

TEST_CASE("ConfigValidation: empty connection_string fails", "[config][validation]") {
    const std::string toml = R"(
[server]
port = 8080

[[databases]]
name = "testdb"
type = "postgresql"
connection_string = ""
)";
    auto result = ConfigLoader::load_from_string(toml);
    CHECK_FALSE(result.success);
    CHECK(result.error_message.find("connection_string") != std::string::npos);
}

TEST_CASE("ConfigValidation: min > max connections fails", "[config][validation]") {
    const std::string toml = R"(
[server]
port = 8080

[[databases]]
name = "testdb"
type = "postgresql"
connection_string = "host=localhost"
min_connections = 50
max_connections = 10
)";
    auto result = ConfigLoader::load_from_string(toml);
    CHECK_FALSE(result.success);
    CHECK(result.error_message.find("min_connections") != std::string::npos);
}

TEST_CASE("ConfigValidation: TLS enabled without cert fails", "[config][validation]") {
    const std::string toml = R"(
[server]
port = 8080

[server.tls]
enabled = true
key_file = "server.key"
)";
    auto result = ConfigLoader::load_from_string(toml);
    CHECK_FALSE(result.success);
    CHECK(result.error_message.find("cert_file") != std::string::npos);
}

TEST_CASE("ConfigValidation: valid minimal config succeeds", "[config][validation]") {
    const std::string toml = R"(
[server]
port = 8080
)";
    auto result = ConfigLoader::load_from_string(toml);
    CHECK(result.success);
}

TEST_CASE("ConfigValidation: zero rate limit tokens fails", "[config][validation]") {
    const std::string toml = R"(
[server]
port = 8080

[rate_limiting]
enabled = true

[rate_limiting.global]
tokens_per_second = 0
)";
    auto result = ConfigLoader::load_from_string(toml);
    CHECK_FALSE(result.success);
    CHECK(result.error_message.find("tokens_per_second") != std::string::npos);
}

TEST_CASE("ConfigValidation: empty database name fails", "[config][validation]") {
    const std::string toml = R"(
[server]
port = 8080

[[databases]]
name = ""
type = "postgresql"
connection_string = "host=localhost"
)";
    auto result = ConfigLoader::load_from_string(toml);
    CHECK_FALSE(result.success);
    CHECK(result.error_message.find("name") != std::string::npos);
}
