#pragma once

#include "auth/iauth_provider.hpp"
#include <chrono>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>

// Forward-declare OpenSSL types
typedef struct evp_pkey_st EVP_PKEY;

namespace sqlproxy {

struct OidcConfig {
    std::string issuer;                         // "https://auth.example.com/realms/prod"
    std::string audience;                       // Required audience (aud claim)
    std::string jwks_uri;                       // If empty, derived from issuer/.well-known
    std::string roles_claim = "roles";          // Claim containing roles array
    std::string user_claim = "sub";             // Claim containing username
    uint32_t jwks_cache_seconds = 3600;         // How long to cache JWKS keys
};

/**
 * @brief OAuth2/OIDC authentication provider
 *
 * Validates Bearer JWT tokens signed with RS256 or ES256.
 * Fetches JWKS from the issuer's well-known endpoint.
 * Caches public keys and refreshes on cache miss (key rotation).
 */
class OidcAuthProvider : public IAuthProvider {
public:
    explicit OidcAuthProvider(OidcConfig config);
    ~OidcAuthProvider() override;

    [[nodiscard]] AuthResult authenticate(
        const std::string& auth_header,
        const std::string& body_user) override;

    [[nodiscard]] std::string name() const override { return "oidc"; }

private:
    // JWT structure
    struct JwtParts {
        std::string header_b64;
        std::string payload_b64;
        std::string signature_b64;
        std::string header_json;
        std::string payload_json;
    };

    // Cached public key
    struct CachedKey {
        EVP_PKEY* key = nullptr;
        std::string algorithm;  // "RS256" or "ES256"
    };

    // Split JWT into parts and base64-decode header/payload
    [[nodiscard]] static bool split_jwt(const std::string& token, JwtParts& parts);

    // Base64url decode
    [[nodiscard]] static std::string base64url_decode(const std::string& input);

    // Extract simple JSON string value by key
    [[nodiscard]] static std::string extract_json_string(const std::string& json, const std::string& key);

    // Extract JSON string array
    [[nodiscard]] static std::vector<std::string> extract_json_string_array(const std::string& json, const std::string& key);

    // Extract integer from JSON
    [[nodiscard]] static int64_t extract_json_int(const std::string& json, const std::string& key);

    // Fetch and parse JWKS from the configured URI
    bool fetch_jwks();

    // Get key by kid (triggers JWKS refresh if not found)
    [[nodiscard]] const CachedKey* get_key(const std::string& kid);

    // Verify RS256 signature
    [[nodiscard]] static bool verify_rs256(EVP_PKEY* key, const std::string& signing_input,
                                           const std::string& signature);

    // Verify ES256 signature
    [[nodiscard]] static bool verify_es256(EVP_PKEY* key, const std::string& signing_input,
                                           const std::string& signature);

    // Parse JWK RSA key (n, e → EVP_PKEY)
    [[nodiscard]] static EVP_PKEY* parse_rsa_jwk(const std::string& n_b64, const std::string& e_b64);

    // Parse JWK EC key (x, y, crv → EVP_PKEY)
    [[nodiscard]] static EVP_PKEY* parse_ec_jwk(const std::string& x_b64, const std::string& y_b64,
                                                 const std::string& crv);

    OidcConfig config_;
    std::string effective_jwks_uri_;

    // Key cache: kid → CachedKey
    std::unordered_map<std::string, CachedKey> key_cache_;
    std::chrono::steady_clock::time_point last_jwks_fetch_{};
    mutable std::shared_mutex keys_mutex_;
};

} // namespace sqlproxy
