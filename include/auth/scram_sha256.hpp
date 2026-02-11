#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace sqlproxy {

// SCRAM-SHA-256 authentication utilities (RFC 5802)
class ScramSha256 {
public:
    // Generate a cryptographically secure random nonce (base64-encoded)
    [[nodiscard]] static std::string generate_nonce(size_t byte_count = 18);

    // PBKDF2-HMAC-SHA-256 key derivation (Hi function in RFC 5802)
    [[nodiscard]] static std::vector<uint8_t> hi(
        std::string_view password,
        const std::vector<uint8_t>& salt,
        uint32_t iterations);

    // HMAC-SHA-256
    [[nodiscard]] static std::vector<uint8_t> hmac_sha256(
        const std::vector<uint8_t>& key,
        std::string_view message);

    [[nodiscard]] static std::vector<uint8_t> hmac_sha256(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& message);

    // SHA-256 hash
    [[nodiscard]] static std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);

    // Base64 encode/decode
    [[nodiscard]] static std::string base64_encode(const std::vector<uint8_t>& data);
    [[nodiscard]] static std::string base64_encode(const uint8_t* data, size_t len);
    [[nodiscard]] static std::vector<uint8_t> base64_decode(std::string_view encoded);

    // XOR two byte vectors of equal length
    [[nodiscard]] static std::vector<uint8_t> xor_bytes(
        const std::vector<uint8_t>& a,
        const std::vector<uint8_t>& b);

    // Generate a random salt
    [[nodiscard]] static std::vector<uint8_t> generate_salt(size_t byte_count = 16);

    // ========================================================================
    // High-level SCRAM helpers for the server side
    // ========================================================================

    // Compute SaltedPassword = Hi(password, salt, iterations)
    [[nodiscard]] static std::vector<uint8_t> salted_password(
        std::string_view password,
        const std::vector<uint8_t>& salt,
        uint32_t iterations);

    // Compute ServerKey = HMAC(SaltedPassword, "Server Key")
    [[nodiscard]] static std::vector<uint8_t> server_key(
        const std::vector<uint8_t>& salted_pw);

    // Compute ClientKey = HMAC(SaltedPassword, "Client Key")
    [[nodiscard]] static std::vector<uint8_t> client_key(
        const std::vector<uint8_t>& salted_pw);

    // Compute StoredKey = SHA-256(ClientKey)
    [[nodiscard]] static std::vector<uint8_t> stored_key(
        const std::vector<uint8_t>& client_key_val);

    // Verify client proof against stored key and auth message
    // Returns true if proof is valid
    [[nodiscard]] static bool verify_client_proof(
        const std::vector<uint8_t>& stored_key_val,
        std::string_view auth_message,
        const std::vector<uint8_t>& client_proof);

    // Compute server signature for the final message
    [[nodiscard]] static std::vector<uint8_t> server_signature(
        const std::vector<uint8_t>& server_key_val,
        std::string_view auth_message);

    // ========================================================================
    // Message parsing helpers
    // ========================================================================

    struct ClientFirstMessage {
        std::string gs2_header;         // "n,,"
        std::string client_first_bare;  // "n=user,r=nonce" (without gs2 header)
        std::string username;
        std::string client_nonce;
        bool valid = false;
    };

    struct ClientFinalMessage {
        std::string channel_binding;    // base64 of gs2 header
        std::string nonce;              // combined nonce
        std::string proof;              // base64 client proof
        std::string without_proof;      // "c=...,r=..." (for auth message)
        bool valid = false;
    };

    // Parse client-first-message from SASLInitialResponse
    [[nodiscard]] static ClientFirstMessage parse_client_first(std::string_view message);

    // Parse client-final-message from SASLResponse
    [[nodiscard]] static ClientFinalMessage parse_client_final(std::string_view message);
};

} // namespace sqlproxy
