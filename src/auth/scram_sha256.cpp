#include "auth/scram_sha256.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cstring>
#include <stdexcept>

namespace sqlproxy {

// ============================================================================
// Low-level crypto primitives
// ============================================================================

std::string ScramSha256::generate_nonce(size_t byte_count) {
    std::vector<uint8_t> bytes(byte_count);
    if (RAND_bytes(bytes.data(), static_cast<int>(byte_count)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return base64_encode(bytes);
}

std::vector<uint8_t> ScramSha256::generate_salt(size_t byte_count) {
    std::vector<uint8_t> salt(byte_count);
    if (RAND_bytes(salt.data(), static_cast<int>(byte_count)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return salt;
}

std::vector<uint8_t> ScramSha256::hi(
    std::string_view password,
    const std::vector<uint8_t>& salt,
    uint32_t iterations) {
    std::vector<uint8_t> result(SHA256_DIGEST_LENGTH);
    if (PKCS5_PBKDF2_HMAC(
            password.data(), static_cast<int>(password.size()),
            salt.data(), static_cast<int>(salt.size()),
            static_cast<int>(iterations),
            EVP_sha256(),
            SHA256_DIGEST_LENGTH, result.data()) != 1) {
        throw std::runtime_error("PKCS5_PBKDF2_HMAC failed");
    }
    return result;
}

std::vector<uint8_t> ScramSha256::hmac_sha256(
    const std::vector<uint8_t>& key,
    std::string_view message) {
    std::vector<uint8_t> result(SHA256_DIGEST_LENGTH);
    unsigned int len = 0;
    if (!HMAC(EVP_sha256(),
              key.data(), static_cast<int>(key.size()),
              reinterpret_cast<const uint8_t*>(message.data()),
              message.size(),
              result.data(), &len)) {
        throw std::runtime_error("HMAC failed");
    }
    result.resize(len);
    return result;
}

std::vector<uint8_t> ScramSha256::hmac_sha256(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& message) {
    std::vector<uint8_t> result(SHA256_DIGEST_LENGTH);
    unsigned int len = 0;
    if (!HMAC(EVP_sha256(),
              key.data(), static_cast<int>(key.size()),
              message.data(), message.size(),
              result.data(), &len)) {
        throw std::runtime_error("HMAC failed");
    }
    result.resize(len);
    return result;
}

std::vector<uint8_t> ScramSha256::sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), result.data());
    return result;
}

std::vector<uint8_t> ScramSha256::xor_bytes(
    const std::vector<uint8_t>& a,
    const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) {
        throw std::runtime_error("XOR: mismatched lengths");
    }
    std::vector<uint8_t> result(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

// ============================================================================
// Base64
// ============================================================================

std::string ScramSha256::base64_encode(const std::vector<uint8_t>& data) {
    return base64_encode(data.data(), data.size());
}

std::string ScramSha256::base64_encode(const uint8_t* data, size_t len) {
    // Output size: ceil(len/3)*4 + 1 for null terminator
    const size_t out_len = ((len + 2) / 3) * 4;
    std::string result(out_len, '\0');

    const int encoded = EVP_EncodeBlock(
        reinterpret_cast<uint8_t*>(result.data()),
        data, static_cast<int>(len));

    if (encoded < 0) {
        throw std::runtime_error("EVP_EncodeBlock failed");
    }
    result.resize(static_cast<size_t>(encoded));
    return result;
}

std::vector<uint8_t> ScramSha256::base64_decode(std::string_view encoded) {
    if (encoded.empty()) return {};

    // Output size is at most 3/4 of input
    const size_t max_out = ((encoded.size() + 3) / 4) * 3;
    std::vector<uint8_t> result(max_out);

    const int decoded = EVP_DecodeBlock(
        result.data(),
        reinterpret_cast<const uint8_t*>(encoded.data()),
        static_cast<int>(encoded.size()));

    if (decoded < 0) {
        throw std::runtime_error("EVP_DecodeBlock failed");
    }

    // EVP_DecodeBlock doesn't account for padding, adjust size
    size_t actual = static_cast<size_t>(decoded);
    if (encoded.size() >= 2 && encoded[encoded.size() - 1] == '=') --actual;
    if (encoded.size() >= 2 && encoded[encoded.size() - 2] == '=') --actual;
    result.resize(actual);
    return result;
}

// ============================================================================
// High-level SCRAM helpers
// ============================================================================

std::vector<uint8_t> ScramSha256::salted_password(
    std::string_view password,
    const std::vector<uint8_t>& salt,
    uint32_t iterations) {
    return hi(password, salt, iterations);
}

std::vector<uint8_t> ScramSha256::server_key(
    const std::vector<uint8_t>& salted_pw) {
    return hmac_sha256(salted_pw, "Server Key");
}

std::vector<uint8_t> ScramSha256::client_key(
    const std::vector<uint8_t>& salted_pw) {
    return hmac_sha256(salted_pw, "Client Key");
}

std::vector<uint8_t> ScramSha256::stored_key(
    const std::vector<uint8_t>& client_key_val) {
    return sha256(client_key_val);
}

bool ScramSha256::verify_client_proof(
    const std::vector<uint8_t>& stored_key_val,
    std::string_view auth_message,
    const std::vector<uint8_t>& client_proof) {
    // ClientSignature = HMAC(StoredKey, AuthMessage)
    const auto client_signature = hmac_sha256(stored_key_val, auth_message);

    // Recovered ClientKey = ClientProof XOR ClientSignature
    const auto recovered_key = xor_bytes(client_proof, client_signature);

    // Verify: H(recovered_key) == StoredKey
    const auto recovered_stored = sha256(recovered_key);
    return recovered_stored == stored_key_val;
}

std::vector<uint8_t> ScramSha256::server_signature(
    const std::vector<uint8_t>& server_key_val,
    std::string_view auth_message) {
    return hmac_sha256(server_key_val, auth_message);
}

// ============================================================================
// Message parsing
// ============================================================================

ScramSha256::ClientFirstMessage ScramSha256::parse_client_first(std::string_view message) {
    ClientFirstMessage result;

    // Format: gs2-header client-first-message-bare
    // gs2-header = "n,," (no channel binding, no authzid)
    // client-first-message-bare = "n=<user>,r=<nonce>"

    // Find end of GS2 header (second comma followed by content)
    size_t gs2_end = 0;
    int comma_count = 0;
    for (size_t i = 0; i < message.size(); ++i) {
        if (message[i] == ',') {
            ++comma_count;
            if (comma_count == 2) {
                gs2_end = i + 1;
                break;
            }
        }
    }

    if (gs2_end == 0 || gs2_end >= message.size()) {
        return result;  // invalid
    }

    result.gs2_header = std::string(message.substr(0, gs2_end));
    result.client_first_bare = std::string(message.substr(gs2_end));

    // Parse client-first-bare: "n=user,r=nonce[,...]"
    const auto& bare = result.client_first_bare;
    size_t pos = 0;

    while (pos < bare.size()) {
        if (pos + 2 <= bare.size() && bare[pos + 1] == '=') {
            const char attr = bare[pos];
            const size_t value_start = pos + 2;
            const size_t value_end = bare.find(',', value_start);
            const std::string value = (value_end == std::string::npos)
                ? std::string(bare.substr(value_start))
                : std::string(bare.substr(value_start, value_end - value_start));

            if (attr == 'n') {
                result.username = value;
            } else if (attr == 'r') {
                result.client_nonce = value;
            }

            pos = (value_end == std::string::npos) ? bare.size() : value_end + 1;
        } else {
            break;
        }
    }

    result.valid = !result.username.empty() && !result.client_nonce.empty();
    return result;
}

ScramSha256::ClientFinalMessage ScramSha256::parse_client_final(std::string_view message) {
    ClientFinalMessage result;

    // Format: "c=<channel_binding>,r=<nonce>,p=<proof>"
    // without_proof = "c=...,r=..."

    size_t pos = 0;
    std::string proof_attr;

    while (pos < message.size()) {
        if (pos + 2 <= message.size() && message[pos + 1] == '=') {
            const char attr = message[pos];
            const size_t value_start = pos + 2;
            const size_t value_end = message.find(',', value_start);
            const std::string value = (value_end == std::string::npos)
                ? std::string(message.substr(value_start))
                : std::string(message.substr(value_start, value_end - value_start));

            if (attr == 'c') {
                result.channel_binding = value;
            } else if (attr == 'r') {
                result.nonce = value;
            } else if (attr == 'p') {
                result.proof = value;
            }

            pos = (value_end == std::string::npos) ? message.size() : value_end + 1;
        } else {
            break;
        }
    }

    // Build without_proof: everything before ",p="
    const auto p_pos = message.find(",p=");
    if (p_pos != std::string_view::npos) {
        result.without_proof = std::string(message.substr(0, p_pos));
    }

    result.valid = !result.channel_binding.empty() &&
                   !result.nonce.empty() &&
                   !result.proof.empty() &&
                   !result.without_proof.empty();
    return result;
}

} // namespace sqlproxy
