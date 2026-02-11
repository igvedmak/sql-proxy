#include "auth/jwt_auth_provider.hpp"
#include "server/http_constants.hpp"
#include "core/utils.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <format>

namespace sqlproxy {

JwtAuthProvider::JwtAuthProvider(JwtConfig config)
    : config_(std::move(config)) {}

IAuthProvider::AuthResult JwtAuthProvider::authenticate(
    const std::string& auth_header,
    const std::string& /*body_user*/) {

    AuthResult result;

    // Extract Bearer token
    if (auth_header.size() <= http::kBearerPrefix.size() ||
        std::string_view(auth_header).substr(0, http::kBearerPrefix.size()) != http::kBearerPrefix) {
        result.error = "No Bearer token";
        return result;
    }

    std::string token(std::string_view(auth_header).substr(http::kBearerPrefix.size()));

    // Split into header.payload.signature
    const auto dot1 = token.find('.');
    if (dot1 == std::string::npos) {
        result.error = "Invalid JWT: missing first dot";
        return result;
    }
    const auto dot2 = token.find('.', dot1 + 1);
    if (dot2 == std::string::npos) {
        result.error = "Invalid JWT: missing second dot";
        return result;
    }

    const std::string header_b64 = token.substr(0, dot1);
    const std::string payload_b64 = token.substr(dot1 + 1, dot2 - dot1 - 1);
    const std::string signature_b64 = token.substr(dot2 + 1);

    // Verify signature (HMAC-SHA256)
    const std::string signing_input = std::format("{}.{}", header_b64, payload_b64);
    if (!config_.secret.empty() && !verify_hmac_sha256(signing_input, signature_b64)) {
        result.error = "Invalid JWT signature";
        return result;
    }

    // Decode payload
    const std::string payload_json = base64url_decode(payload_b64);
    if (payload_json.empty()) {
        result.error = "Invalid JWT: failed to decode payload";
        return result;
    }

    // Check expiration
    const std::string exp_str = extract_json_string(payload_json, "exp");
    if (const auto exp_time = utils::try_parse_int<long long>(exp_str)) {
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if (now > *exp_time) {
            result.error = "JWT expired";
            return result;
        }
    }

    // Verify issuer
    if (!config_.issuer.empty()) {
        const std::string iss = extract_json_string(payload_json, "iss");
        if (iss != config_.issuer) {
            result.error = std::format("JWT issuer mismatch: expected={}, got={}", config_.issuer, iss);
            return result;
        }
    }

    // Verify audience
    if (!config_.audience.empty()) {
        const std::string aud = extract_json_string(payload_json, "aud");
        if (aud != config_.audience) {
            result.error = std::format("JWT audience mismatch: expected={}, got={}", config_.audience, aud);
            return result;
        }
    }

    // Extract user from 'sub' claim
    result.user = extract_json_string(payload_json, "sub");
    if (result.user.empty()) {
        result.error = "JWT missing 'sub' claim";
        return result;
    }

    // Extract roles
    result.roles = extract_json_string_array(payload_json, config_.roles_claim);
    if (result.roles.empty()) {
        result.roles.push_back("user");  // Default role
    }

    result.authenticated = true;
    return result;
}

bool JwtAuthProvider::verify_hmac_sha256(
    const std::string& signing_input,
    const std::string& signature_b64) const {

    const std::string expected_sig = base64url_decode(signature_b64);
    if (expected_sig.empty()) return false;

    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;

    HMAC(EVP_sha256(),
         config_.secret.data(), static_cast<int>(config_.secret.size()),
         reinterpret_cast<const unsigned char*>(signing_input.data()),
         signing_input.size(),
         hmac_result, &hmac_len);

    if (hmac_len != expected_sig.size()) return false;
    return CRYPTO_memcmp(hmac_result, expected_sig.data(), hmac_len) == 0;
}

std::string JwtAuthProvider::base64url_decode(const std::string& input) {
    // Convert base64url to standard base64
    std::string b64 = input;
    std::replace(b64.begin(), b64.end(), '-', '+');
    std::replace(b64.begin(), b64.end(), '_', '/');

    // Add padding
    while (b64.size() % 4 != 0) {
        b64 += '=';
    }

    // Decode using OpenSSL EVP
    const size_t max_decoded_len = (b64.size() / 4) * 3 + 3;
    std::string decoded(max_decoded_len, '\0');

    EVP_ENCODE_CTX* ctx = EVP_ENCODE_CTX_new();
    if (!ctx) return "";

    EVP_DecodeInit(ctx);
    int out_len = 0;
    int tmp_len = 0;

    int rc = EVP_DecodeUpdate(ctx,
        reinterpret_cast<unsigned char*>(decoded.data()), &out_len,
        reinterpret_cast<const unsigned char*>(b64.data()),
        static_cast<int>(b64.size()));

    if (rc < 0) {
        EVP_ENCODE_CTX_free(ctx);
        return "";
    }

    rc = EVP_DecodeFinal(ctx,
        reinterpret_cast<unsigned char*>(decoded.data()) + out_len, &tmp_len);
    EVP_ENCODE_CTX_free(ctx);

    if (rc < 0) return "";

    decoded.resize(out_len + tmp_len);
    return decoded;
}

std::string JwtAuthProvider::extract_json_string(const std::string& json, const std::string& key) {
    // Simple JSON string extraction (no dependency on JSON library)
    const std::string search = std::format("\"{}\"", key);
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";

    pos += search.size();
    // Skip whitespace and colon
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':')) ++pos;

    if (pos >= json.size()) return "";

    // Handle numeric values (for "exp" claim)
    if (json[pos] != '"') {
        const size_t end = json.find_first_of(",}", pos);
        if (end == std::string::npos) return "";
        std::string value = json.substr(pos, end - pos);
        // Trim whitespace
        while (!value.empty() && value.back() == ' ') value.pop_back();
        return value;
    }

    // String value
    ++pos;  // Skip opening quote
    const size_t end = json.find('"', pos);
    if (end == std::string::npos) return "";

    return json.substr(pos, end - pos);
}

std::vector<std::string> JwtAuthProvider::extract_json_string_array(
    const std::string& json, const std::string& key) {

    std::vector<std::string> result;
    const std::string search = std::format("\"{}\"", key);
    auto pos = json.find(search);
    if (pos == std::string::npos) return result;

    pos += search.size();
    while (pos < json.size() && json[pos] != '[') ++pos;
    if (pos >= json.size()) return result;

    ++pos;  // Skip '['
    while (pos < json.size() && json[pos] != ']') {
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == ',')) ++pos;
        if (pos >= json.size() || json[pos] == ']') break;

        if (json[pos] == '"') {
            ++pos;
            const size_t end = json.find('"', pos);
            if (end == std::string::npos) break;
            result.push_back(json.substr(pos, end - pos));
            pos = end + 1;
        } else {
            ++pos;
        }
    }
    return result;
}

} // namespace sqlproxy
