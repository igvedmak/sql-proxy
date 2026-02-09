#include <catch2/catch_test_macros.hpp>
#include "auth/iauth_provider.hpp"
#include "auth/jwt_auth_provider.hpp"
#include "auth/auth_chain.hpp"
#include "config/config_loader.hpp"

#include <openssl/hmac.h>
#include <openssl/evp.h>

using namespace sqlproxy;

namespace {

// Helper: create a valid JWT token with HMAC-SHA256
std::string create_test_jwt(const std::string& payload_json, const std::string& secret) {
    // Base64url encode
    auto b64url_encode = [](const std::string& input) -> std::string {
        static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string result;
        for (size_t i = 0; i < input.size(); i += 3) {
            uint32_t a = static_cast<uint8_t>(input[i]);
            uint32_t b = (i + 1 < input.size()) ? static_cast<uint8_t>(input[i + 1]) : 0;
            uint32_t c = (i + 2 < input.size()) ? static_cast<uint8_t>(input[i + 2]) : 0;
            uint32_t triple = (a << 16) | (b << 8) | c;

            size_t remaining = input.size() - i;
            int nchars = (remaining >= 3) ? 4 : static_cast<int>(remaining) + 1;

            for (int j = 0; j < nchars; ++j) {
                result += b64[(triple >> (18 - j * 6)) & 0x3F];
            }
        }
        // Convert to base64url
        for (auto& ch : result) {
            if (ch == '+') ch = '-';
            else if (ch == '/') ch = '_';
        }
        return result;
    };

    std::string header = R"({"alg":"HS256","typ":"JWT"})";
    std::string header_b64 = b64url_encode(header);
    std::string payload_b64 = b64url_encode(payload_json);

    std::string signing_input = header_b64 + "." + payload_b64;

    // HMAC-SHA256
    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
         reinterpret_cast<const unsigned char*>(signing_input.data()),
         signing_input.size(), hmac_result, &hmac_len);

    std::string sig(reinterpret_cast<char*>(hmac_result), hmac_len);
    std::string sig_b64 = b64url_encode(sig);

    return signing_input + "." + sig_b64;
}

} // anonymous namespace

TEST_CASE("JWT auth provider - valid token", "[auth][jwt]") {
    JwtConfig config;
    config.secret = "test-secret-key-for-jwt";
    config.issuer = "test-issuer";
    config.audience = "sql-proxy";
    config.roles_claim = "roles";

    JwtAuthProvider provider(config);

    // Create a valid token
    long long future_exp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() + 3600;

    std::string payload = R"({"sub":"analyst","iss":"test-issuer","aud":"sql-proxy","exp":)" +
        std::to_string(future_exp) + R"(,"roles":["user","analyst"]})";

    std::string token = create_test_jwt(payload, config.secret);
    std::string auth_header = "Bearer " + token;

    auto result = provider.authenticate(auth_header, "");
    REQUIRE(result.authenticated);
    REQUIRE(result.user == "analyst");
    REQUIRE(result.roles.size() >= 1);
}

TEST_CASE("JWT auth provider - no bearer token", "[auth][jwt]") {
    JwtConfig config;
    config.secret = "test-secret";
    JwtAuthProvider provider(config);

    auto result = provider.authenticate("", "");
    REQUIRE_FALSE(result.authenticated);
    REQUIRE_FALSE(result.error.empty());
}

TEST_CASE("JWT auth provider - invalid token format", "[auth][jwt]") {
    JwtConfig config;
    config.secret = "test-secret";
    JwtAuthProvider provider(config);

    auto result = provider.authenticate("Bearer invalid-token", "");
    REQUIRE_FALSE(result.authenticated);
}

TEST_CASE("Auth chain - tries providers in order", "[auth][chain]") {
    AuthChain chain;

    // Create a JWT provider with a known secret
    auto jwt_config = JwtConfig{};
    jwt_config.secret = "chain-test-secret";
    chain.add_provider(std::make_shared<JwtAuthProvider>(std::move(jwt_config)));

    REQUIRE(chain.provider_count() == 1);

    // No valid auth header → should fail
    auto result = chain.authenticate("", "analyst");
    REQUIRE_FALSE(result.authenticated);
}

TEST_CASE("Auth config parsed from TOML", "[auth][config]") {
    std::string toml = R"(
[auth]
provider = "jwt"

[auth.jwt]
issuer = "https://auth.company.com"
audience = "sql-proxy"
secret = "my-secret"
roles_claim = "roles"
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    REQUIRE(result.config.auth.provider == "jwt");
    REQUIRE(result.config.auth.jwt_issuer == "https://auth.company.com");
    REQUIRE(result.config.auth.jwt_audience == "sql-proxy");
    REQUIRE(result.config.auth.jwt_secret == "my-secret");
}

TEST_CASE("Auth config defaults to api_key", "[auth][config]") {
    std::string toml = R"(
[server]
port = 8080
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    REQUIRE(result.config.auth.provider == "api_key");
}
