#include <catch2/catch_test_macros.hpp>
#include "core/types.hpp"
#include "config/config_loader.hpp"

using namespace sqlproxy;

TEST_CASE("TLS config defaults to disabled", "[tls]") {
    TlsConfig tls;
    REQUIRE_FALSE(tls.enabled);
    REQUIRE(tls.cert_file.empty());
    REQUIRE(tls.key_file.empty());
    REQUIRE(tls.ca_file.empty());
    REQUIRE_FALSE(tls.require_client_cert);
}

TEST_CASE("TLS config in ServerConfig", "[tls]") {
    ServerConfig cfg;
    REQUIRE_FALSE(cfg.tls.enabled);

    cfg.tls.enabled = true;
    cfg.tls.cert_file = "/etc/ssl/server.crt";
    cfg.tls.key_file = "/etc/ssl/server.key";
    REQUIRE(cfg.tls.enabled);
    REQUIRE(cfg.tls.cert_file == "/etc/ssl/server.crt");
}

TEST_CASE("TLS config parsed from TOML", "[tls]") {
    std::string toml = R"(
[server]
host = "0.0.0.0"
port = 8443

[server.tls]
enabled = true
cert_file = "config/server.crt"
key_file = "config/server.key"
ca_file = "config/ca.crt"
require_client_cert = true
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    REQUIRE(result.config.server.tls.enabled);
    REQUIRE(result.config.server.tls.cert_file == "config/server.crt");
    REQUIRE(result.config.server.tls.key_file == "config/server.key");
    REQUIRE(result.config.server.tls.ca_file == "config/ca.crt");
    REQUIRE(result.config.server.tls.require_client_cert);
}

TEST_CASE("TLS disabled by default in TOML", "[tls]") {
    std::string toml = R"(
[server]
host = "0.0.0.0"
port = 8080
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    REQUIRE_FALSE(result.config.server.tls.enabled);
}
