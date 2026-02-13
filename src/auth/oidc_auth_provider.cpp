#include "auth/oidc_auth_provider.hpp"
#include "core/json.hpp"
#include "core/utils.hpp"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <algorithm>
#include <cstring>
#include <format>

// Simple HTTP fetch via libcurl (or fallback)
// For JWKS we use a minimal approach: shell out to curl or use OpenSSL BIO
// In production you'd use libcurl. Here we use a simple socket-based fetch.
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/ssl.h>

namespace sqlproxy {

namespace {

// Minimal HTTPS GET (returns body, empty on error)
std::string https_get(const std::string& url) {
    // Parse URL: https://host[:port]/path
    if (url.substr(0, 8) != "https://") {
        utils::log::error(std::format("OIDC: only HTTPS supported, got: {}", url));
        return {};
    }

    const auto host_start = url.begin() + 8;
    const auto path_pos = std::find(host_start, url.end(), '/');
    std::string host_port(host_start, path_pos);
    std::string path = (path_pos != url.end()) ? std::string(path_pos, url.end()) : "/";

    std::string host = host_port;
    std::string port = "443";
    if (const auto colon = host_port.find(':'); colon != std::string::npos) {
        host = host_port.substr(0, colon);
        port = host_port.substr(colon + 1);
    }

    // DNS resolve
    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &result) != 0 || !result) {
        utils::log::error(std::format("OIDC: DNS resolution failed for {}", host));
        return {};
    }

    int fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(result);
        return {};
    }

    if (connect(fd, result->ai_addr, result->ai_addrlen) < 0) {
        freeaddrinfo(result);
        close(fd);
        utils::log::error(std::format("OIDC: connect failed to {}:{}", host, port));
        return {};
    }
    freeaddrinfo(result);

    // TLS handshake
    auto* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(fd); return {}; }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    auto* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host.c_str());
    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        utils::log::error(std::format("OIDC: TLS handshake failed to {}", host));
        return {};
    }

    // Send HTTP request
    std::string req = std::format(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        path, host);
    SSL_write(ssl, req.c_str(), static_cast<int>(req.size()));

    // Read response
    std::string response;
    char buf[4096];
    int n;
    while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0) {
        response.append(buf, static_cast<size_t>(n));
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);

    // Extract body after \r\n\r\n
    const auto body_start = response.find("\r\n\r\n");
    if (body_start == std::string::npos) return {};

    std::string body = response.substr(body_start + 4);

    // Handle chunked transfer encoding
    if (response.find("Transfer-Encoding: chunked") != std::string::npos) {
        std::string decoded;
        size_t pos = 0;
        while (pos < body.size()) {
            const auto crlf = body.find("\r\n", pos);
            if (crlf == std::string::npos) break;
            const size_t chunk_size = std::stoull(body.substr(pos, crlf - pos), nullptr, 16);
            if (chunk_size == 0) break;
            pos = crlf + 2;
            if (pos + chunk_size > body.size()) break;
            decoded.append(body, pos, chunk_size);
            pos += chunk_size + 2;  // skip \r\n after chunk
        }
        return decoded;
    }

    return body;
}

// JWK entry parsed from JWKS
struct JwkEntry {
    std::string kid;
    std::string kty;    // "RSA" or "EC"
    std::string alg;    // "RS256" or "ES256"
    std::string use;    // "sig"
    // RSA fields
    std::string n, e;
    // EC fields
    std::string x, y, crv;
};

std::vector<JwkEntry> parse_jwks(const std::string& json_str) {
    std::vector<JwkEntry> keys;

    JsonValue doc;
    try {
        doc = JsonValue::parse(json_str);
    } catch (const JsonValue::parse_error&) {
        return keys;
    }

    const auto keys_arr = doc["keys"];
    if (!keys_arr.is_array()) return keys;

    for (const auto& k : keys_arr) {
        if (!k.is_object()) continue;

        JwkEntry entry;
        entry.kid = k.value("kid", std::string{});
        entry.kty = k.value("kty", std::string{});
        entry.alg = k.value("alg", std::string{});
        entry.use = k.value("use", std::string{});
        entry.n   = k.value("n",   std::string{});
        entry.e   = k.value("e",   std::string{});
        entry.x   = k.value("x",   std::string{});
        entry.y   = k.value("y",   std::string{});
        entry.crv = k.value("crv", std::string{});

        if (!entry.kid.empty() && !entry.kty.empty()) {
            keys.emplace_back(std::move(entry));
        }
    }

    return keys;
}

} // anonymous namespace

// ============================================================================
// OidcAuthProvider
// ============================================================================

OidcAuthProvider::OidcAuthProvider(OidcConfig config)
    : config_(std::move(config)) {
    if (!config_.jwks_uri.empty()) {
        effective_jwks_uri_ = config_.jwks_uri;
    } else if (!config_.issuer.empty()) {
        // Derive from well-known
        effective_jwks_uri_ = config_.issuer;
        if (effective_jwks_uri_.back() != '/') effective_jwks_uri_ += '/';
        effective_jwks_uri_ += ".well-known/openid-configuration";
    }
}

OidcAuthProvider::~OidcAuthProvider() {
    for (auto& [kid, cached] : key_cache_) {
        if (cached.key) EVP_PKEY_free(cached.key);
    }
}

IAuthProvider::AuthResult OidcAuthProvider::authenticate(
    const std::string& auth_header,
    const std::string& /*body_user*/) {

    // Only handle Bearer tokens
    constexpr std::string_view bearer_prefix = "Bearer ";
    if (auth_header.size() <= bearer_prefix.size() ||
        std::string_view(auth_header).substr(0, bearer_prefix.size()) != bearer_prefix) {
        return {.error = "No Bearer token"};
    }

    const std::string token(auth_header.substr(bearer_prefix.size()));

    // Split JWT
    JwtParts parts;
    if (!split_jwt(token, parts)) {
        return {.error = "Invalid JWT format"};
    }

    // Parse header and payload JSON using Glaze
    JsonValue header_claims, payload_claims;
    try {
        header_claims = JsonValue::parse(parts.header_json);
        payload_claims = JsonValue::parse(parts.payload_json);
    } catch (const JsonValue::parse_error&) {
        return {.error = "Invalid JWT: malformed JSON"};
    }

    // Extract algorithm and kid from header
    const std::string alg = header_claims.value("alg", std::string{});
    const std::string kid = header_claims.value("kid", std::string{});

    if (alg != "RS256" && alg != "ES256") {
        return {.error = std::format("Unsupported algorithm: {}", alg)};
    }

    if (kid.empty()) {
        return {.error = "JWT missing kid header"};
    }

    // Get the public key
    const auto* cached_key = get_key(kid);
    if (!cached_key) {
        return {.error = std::format("Unknown key id: {}", kid)};
    }

    // Verify signature
    const std::string signing_input = parts.header_b64 + "." + parts.payload_b64;
    const std::string signature = base64url_decode(parts.signature_b64);

    bool sig_valid = false;
    if (alg == "RS256") {
        sig_valid = verify_rs256(cached_key->key, signing_input, signature);
    } else if (alg == "ES256") {
        sig_valid = verify_es256(cached_key->key, signing_input, signature);
    }

    if (!sig_valid) {
        return {.error = "JWT signature verification failed"};
    }

    // Validate claims
    const std::string iss = payload_claims.value("iss", std::string{});
    if (!config_.issuer.empty() && iss != config_.issuer) {
        return {.error = std::format("Invalid issuer: expected '{}', got '{}'", config_.issuer, iss)};
    }

    const std::string aud = payload_claims.value("aud", std::string{});
    if (!config_.audience.empty() && aud != config_.audience) {
        return {.error = std::format("Invalid audience: expected '{}', got '{}'", config_.audience, aud)};
    }

    // Check expiration
    if (payload_claims.contains("exp") && payload_claims["exp"].is_number()) {
        const auto exp = payload_claims["exp"].get<int64_t>();
        if (exp > 0) {
            const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            if (now > exp) {
                return {.error = "JWT expired"};
            }
        }
    }

    // Extract user
    const std::string user = payload_claims.value(config_.user_claim, std::string{});
    if (user.empty()) {
        return {.error = std::format("Missing user claim '{}'", config_.user_claim)};
    }

    // Extract roles (supports nested claim paths like "realm_access.roles")
    std::vector<std::string> roles;
    JsonValue roles_node;
    const auto dot = config_.roles_claim.find('.');
    if (dot != std::string::npos) {
        const auto outer = payload_claims[config_.roles_claim.substr(0, dot)];
        roles_node = outer[config_.roles_claim.substr(dot + 1)];
    } else {
        roles_node = payload_claims[config_.roles_claim];
    }
    if (roles_node.is_array()) {
        for (const auto& r : roles_node) {
            if (r.is_string()) roles.push_back(r.get<std::string>());
        }
    }

    return {
        .authenticated = true,
        .user = user,
        .roles = roles
    };
}

bool OidcAuthProvider::split_jwt(const std::string& token, JwtParts& parts) {
    const auto dot1 = token.find('.');
    if (dot1 == std::string::npos) return false;
    const auto dot2 = token.find('.', dot1 + 1);
    if (dot2 == std::string::npos) return false;
    if (token.find('.', dot2 + 1) != std::string::npos) return false;  // Only 3 parts

    parts.header_b64 = token.substr(0, dot1);
    parts.payload_b64 = token.substr(dot1 + 1, dot2 - dot1 - 1);
    parts.signature_b64 = token.substr(dot2 + 1);

    parts.header_json = base64url_decode(parts.header_b64);
    parts.payload_json = base64url_decode(parts.payload_b64);

    return !parts.header_json.empty() && !parts.payload_json.empty();
}

std::string OidcAuthProvider::base64url_decode(const std::string& input) {
    // Convert base64url to standard base64
    std::string b64 = input;
    std::replace(b64.begin(), b64.end(), '-', '+');
    std::replace(b64.begin(), b64.end(), '_', '/');
    while (b64.size() % 4 != 0) b64 += '=';

    // Decode using OpenSSL EVP
    const size_t max_len = (b64.size() * 3) / 4 + 1;
    std::string output(max_len, '\0');

    auto* bio = BIO_new_mem_buf(b64.data(), static_cast<int>(b64.size()));
    auto* b64_filter = BIO_new(BIO_f_base64());
    BIO_set_flags(b64_filter, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64_filter, bio);

    const int decoded_len = BIO_read(bio, output.data(), static_cast<int>(max_len));
    BIO_free_all(bio);

    if (decoded_len <= 0) return {};
    output.resize(static_cast<size_t>(decoded_len));
    return output;
}

bool OidcAuthProvider::fetch_jwks() {
    std::string jwks_uri = effective_jwks_uri_;

    // If URI is a well-known endpoint, fetch it first to get actual JWKS URI
    if (jwks_uri.find(".well-known/openid-configuration") != std::string::npos) {
        const auto discovery = https_get(jwks_uri);
        if (discovery.empty()) {
            utils::log::error(std::format("OIDC: failed to fetch discovery from {}", jwks_uri));
            return false;
        }
        std::string actual_jwks_uri;
        try {
            const auto disc_json = JsonValue::parse(discovery);
            actual_jwks_uri = disc_json.value("jwks_uri", std::string{});
        } catch (const JsonValue::parse_error&) {
            actual_jwks_uri.clear();
        }
        if (actual_jwks_uri.empty()) {
            utils::log::error("OIDC: discovery response missing jwks_uri");
            return false;
        }
        jwks_uri = actual_jwks_uri;
        effective_jwks_uri_ = actual_jwks_uri;  // Cache for next time
    }

    const auto jwks_json = https_get(jwks_uri);
    if (jwks_json.empty()) {
        utils::log::error(std::format("OIDC: failed to fetch JWKS from {}", jwks_uri));
        return false;
    }

    const auto entries = parse_jwks(jwks_json);
    if (entries.empty()) {
        utils::log::warn("OIDC: JWKS contains no keys");
        return false;
    }

    // Parse keys and update cache under write lock
    std::unordered_map<std::string, CachedKey> new_cache;
    for (const auto& entry : entries) {
        if (entry.use == "enc") continue;  // Skip encryption keys

        CachedKey ck;
        if (entry.kty == "RSA") {
            ck.key = parse_rsa_jwk(entry.n, entry.e);
            ck.algorithm = entry.alg.empty() ? "RS256" : entry.alg;
        } else if (entry.kty == "EC") {
            ck.key = parse_ec_jwk(entry.x, entry.y, entry.crv);
            ck.algorithm = entry.alg.empty() ? "ES256" : entry.alg;
        }

        if (ck.key) {
            new_cache[entry.kid] = ck;
        }
    }

    {
        std::unique_lock lock(keys_mutex_);
        // Free old keys
        for (auto& [kid, cached] : key_cache_) {
            if (cached.key) EVP_PKEY_free(cached.key);
        }
        key_cache_ = std::move(new_cache);
        last_jwks_fetch_ = std::chrono::steady_clock::now();
    }

    utils::log::info(std::format("OIDC: loaded {} keys from JWKS", key_cache_.size()));
    return true;
}

const OidcAuthProvider::CachedKey* OidcAuthProvider::get_key(const std::string& kid) {
    // Fast path: shared lock
    {
        std::shared_lock lock(keys_mutex_);
        const auto it = key_cache_.find(kid);
        if (it != key_cache_.end()) return &it->second;
    }

    // Cache miss — refresh JWKS (key rotation)
    const auto now = std::chrono::steady_clock::now();
    if (now - last_jwks_fetch_ < std::chrono::seconds(10)) {
        // Don't hammer the JWKS endpoint
        return nullptr;
    }

    if (!fetch_jwks()) return nullptr;

    // Try again
    std::shared_lock lock(keys_mutex_);
    const auto it = key_cache_.find(kid);
    return (it != key_cache_.end()) ? &it->second : nullptr;
}

bool OidcAuthProvider::verify_rs256(EVP_PKEY* key, const std::string& signing_input,
                                     const std::string& signature) {
    auto* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, key) == 1 &&
        EVP_DigestVerifyUpdate(ctx, signing_input.data(), signing_input.size()) == 1 &&
        EVP_DigestVerifyFinal(ctx,
            reinterpret_cast<const unsigned char*>(signature.data()),
            signature.size()) == 1) {
        ok = true;
    }

    EVP_MD_CTX_free(ctx);
    return ok;
}

bool OidcAuthProvider::verify_es256(EVP_PKEY* key, const std::string& signing_input,
                                     const std::string& signature) {
    // ES256 JWS signature is r||s (64 bytes = 2x32), need to convert to DER
    if (signature.size() != 64) return false;

    // Build DER-encoded ECDSA-Sig-Value
    BIGNUM* r = BN_bin2bn(reinterpret_cast<const unsigned char*>(signature.data()), 32, nullptr);
    BIGNUM* s = BN_bin2bn(reinterpret_cast<const unsigned char*>(signature.data() + 32), 32, nullptr);
    if (!r || !s) {
        BN_free(r);
        BN_free(s);
        return false;
    }

    ECDSA_SIG* ec_sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(ec_sig, r, s);  // Takes ownership

    // Convert to DER
    unsigned char* der = nullptr;
    const int der_len = i2d_ECDSA_SIG(ec_sig, &der);
    ECDSA_SIG_free(ec_sig);

    if (der_len <= 0 || !der) return false;

    auto* ctx = EVP_MD_CTX_new();
    bool ok = false;
    if (ctx &&
        EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, key) == 1 &&
        EVP_DigestVerifyUpdate(ctx, signing_input.data(), signing_input.size()) == 1 &&
        EVP_DigestVerifyFinal(ctx, der, static_cast<size_t>(der_len)) == 1) {
        ok = true;
    }

    EVP_MD_CTX_free(ctx);
    OPENSSL_free(der);
    return ok;
}

EVP_PKEY* OidcAuthProvider::parse_rsa_jwk(const std::string& n_b64, const std::string& e_b64) {
    const std::string n_bin = base64url_decode(n_b64);
    const std::string e_bin = base64url_decode(e_b64);

    if (n_bin.empty() || e_bin.empty()) return nullptr;

    BIGNUM* n = BN_bin2bn(reinterpret_cast<const unsigned char*>(n_bin.data()),
                          static_cast<int>(n_bin.size()), nullptr);
    BIGNUM* e = BN_bin2bn(reinterpret_cast<const unsigned char*>(e_bin.data()),
                          static_cast<int>(e_bin.size()), nullptr);
    if (!n || !e) {
        BN_free(n);
        BN_free(e);
        return nullptr;
    }

    RSA* rsa = RSA_new();
    if (RSA_set0_key(rsa, n, e, nullptr) != 1) {
        RSA_free(rsa);
        return nullptr;
    }

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    return pkey;
}

EVP_PKEY* OidcAuthProvider::parse_ec_jwk(const std::string& x_b64, const std::string& y_b64,
                                           const std::string& crv) {
    const std::string x_bin = base64url_decode(x_b64);
    const std::string y_bin = base64url_decode(y_b64);

    if (x_bin.empty() || y_bin.empty()) return nullptr;

    // Map crv to NID
    int nid = NID_X9_62_prime256v1;  // P-256 default
    if (crv == "P-384") nid = NID_secp384r1;
    else if (crv == "P-521") nid = NID_secp521r1;

    EC_KEY* ec = EC_KEY_new_by_curve_name(nid);
    if (!ec) return nullptr;

    BIGNUM* x = BN_bin2bn(reinterpret_cast<const unsigned char*>(x_bin.data()),
                          static_cast<int>(x_bin.size()), nullptr);
    BIGNUM* y = BN_bin2bn(reinterpret_cast<const unsigned char*>(y_bin.data()),
                          static_cast<int>(y_bin.size()), nullptr);

    if (!x || !y || EC_KEY_set_public_key_affine_coordinates(ec, x, y) != 1) {
        BN_free(x);
        BN_free(y);
        EC_KEY_free(ec);
        return nullptr;
    }
    BN_free(x);
    BN_free(y);

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    return pkey;
}

} // namespace sqlproxy
