#include <catch2/catch_test_macros.hpp>
#include "auth/scram_sha256.hpp"

using namespace sqlproxy;

TEST_CASE("ScramSha256 base64 encode/decode", "[scram]") {
    // Empty
    REQUIRE(ScramSha256::base64_encode(std::vector<uint8_t>{}) == "");

    // Known vectors
    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    const std::string encoded = ScramSha256::base64_encode(data);
    REQUIRE(encoded == "SGVsbG8=");

    const auto decoded = ScramSha256::base64_decode(encoded);
    REQUIRE(decoded == data);

    // Round-trip with binary data
    std::vector<uint8_t> binary = {0x00, 0xFF, 0x80, 0x7F, 0x01};
    const auto rt = ScramSha256::base64_decode(ScramSha256::base64_encode(binary));
    REQUIRE(rt == binary);
}

TEST_CASE("ScramSha256 nonce generation", "[scram]") {
    const auto nonce1 = ScramSha256::generate_nonce();
    const auto nonce2 = ScramSha256::generate_nonce();

    // Nonces should be non-empty and different
    REQUIRE(!nonce1.empty());
    REQUIRE(!nonce2.empty());
    REQUIRE(nonce1 != nonce2);
}

TEST_CASE("ScramSha256 SHA-256", "[scram]") {
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    std::vector<uint8_t> empty;
    const auto hash = ScramSha256::sha256(empty);
    REQUIRE(hash.size() == 32);
    REQUIRE(hash[0] == 0xe3);
    REQUIRE(hash[1] == 0xb0);
    REQUIRE(hash[31] == 0x55);
}

TEST_CASE("ScramSha256 HMAC-SHA-256", "[scram]") {
    // Test vector from RFC 4231
    std::vector<uint8_t> key(20, 0x0b);
    const auto result = ScramSha256::hmac_sha256(key, "Hi There");
    REQUIRE(result.size() == 32);
    // Expected: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    REQUIRE(result[0] == 0xb0);
    REQUIRE(result[1] == 0x34);
}

TEST_CASE("ScramSha256 XOR bytes", "[scram]") {
    std::vector<uint8_t> a = {0xFF, 0x00, 0xAA};
    std::vector<uint8_t> b = {0x0F, 0xF0, 0x55};
    const auto result = ScramSha256::xor_bytes(a, b);
    REQUIRE(result == std::vector<uint8_t>{0xF0, 0xF0, 0xFF});
}

TEST_CASE("ScramSha256 PBKDF2 (Hi function)", "[scram]") {
    // Derive a key and verify it's 32 bytes (SHA-256 output)
    std::vector<uint8_t> salt = {0x01, 0x02, 0x03, 0x04};
    const auto derived = ScramSha256::hi("password", salt, 4096);
    REQUIRE(derived.size() == 32);

    // Same input should produce same output (deterministic)
    const auto derived2 = ScramSha256::hi("password", salt, 4096);
    REQUIRE(derived == derived2);

    // Different password should produce different output
    const auto derived3 = ScramSha256::hi("other", salt, 4096);
    REQUIRE(derived != derived3);
}

TEST_CASE("ScramSha256 full SCRAM flow", "[scram]") {
    // Simulate a complete SCRAM-SHA-256 exchange

    const std::string password = "pencil";
    const uint32_t iterations = 4096;
    const auto salt = ScramSha256::generate_salt(16);
    const auto server_nonce = ScramSha256::generate_nonce();

    // 1. Client sends client-first-message
    const std::string client_nonce = ScramSha256::generate_nonce();
    const std::string client_first_bare = "n=user,r=" + client_nonce;
    const std::string client_first = "n,," + client_first_bare;

    // 2. Server generates server-first-message
    const std::string combined_nonce = client_nonce + server_nonce;
    const std::string salt_b64 = ScramSha256::base64_encode(salt);
    const std::string server_first = "r=" + combined_nonce + ",s=" + salt_b64 +
                                     ",i=" + std::to_string(iterations);

    // 3. Client computes proof
    const auto salted_pw = ScramSha256::salted_password(password, salt, iterations);
    const auto ck = ScramSha256::client_key(salted_pw);
    const auto sk = ScramSha256::stored_key(ck);
    const auto svk = ScramSha256::server_key(salted_pw);

    const std::string channel_binding = ScramSha256::base64_encode(
        std::vector<uint8_t>{'n', ',', ','});
    const std::string client_final_without_proof =
        "c=" + channel_binding + ",r=" + combined_nonce;

    const std::string auth_message =
        client_first_bare + "," + server_first + "," + client_final_without_proof;

    const auto client_sig = ScramSha256::hmac_sha256(sk, auth_message);
    const auto client_proof = ScramSha256::xor_bytes(ck, client_sig);

    // 4. Server verifies client proof
    REQUIRE(ScramSha256::verify_client_proof(sk, auth_message, client_proof));

    // 5. Server computes server signature
    const auto srv_sig = ScramSha256::server_signature(svk, auth_message);
    REQUIRE(!srv_sig.empty());
    REQUIRE(srv_sig.size() == 32);

    // Client can verify server signature too (same computation)
    const auto expected_srv_sig = ScramSha256::hmac_sha256(svk, auth_message);
    REQUIRE(srv_sig == expected_srv_sig);
}

TEST_CASE("ScramSha256 parse client-first-message", "[scram]") {
    const auto msg = ScramSha256::parse_client_first("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL");

    REQUIRE(msg.valid);
    REQUIRE(msg.gs2_header == "n,,");
    REQUIRE(msg.username == "user");
    REQUIRE(msg.client_nonce == "fyko+d2lbbFgONRv9qkxdawL");
    REQUIRE(msg.client_first_bare == "n=user,r=fyko+d2lbbFgONRv9qkxdawL");
}

TEST_CASE("ScramSha256 parse client-final-message", "[scram]") {
    const auto msg = ScramSha256::parse_client_final(
        "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=");

    REQUIRE(msg.valid);
    REQUIRE(msg.channel_binding == "biws");
    REQUIRE(msg.nonce == "fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j");
    REQUIRE(msg.proof == "v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=");
    REQUIRE(msg.without_proof == "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j");
}

TEST_CASE("ScramSha256 invalid client-first-message", "[scram]") {
    // Missing username
    auto msg = ScramSha256::parse_client_first("n,,r=nonce");
    REQUIRE_FALSE(msg.valid);

    // Empty
    msg = ScramSha256::parse_client_first("");
    REQUIRE_FALSE(msg.valid);
}

TEST_CASE("ScramSha256 verify rejects wrong proof", "[scram]") {
    const auto salt = ScramSha256::generate_salt();
    const auto salted_pw = ScramSha256::salted_password("password", salt, 4096);
    const auto ck = ScramSha256::client_key(salted_pw);
    const auto sk = ScramSha256::stored_key(ck);

    // Correct proof
    const std::string auth_msg = "n=user,r=abc,r=abc123,s=xyz,i=4096,c=biws,r=abc123";
    const auto client_sig = ScramSha256::hmac_sha256(sk, auth_msg);
    const auto good_proof = ScramSha256::xor_bytes(ck, client_sig);
    REQUIRE(ScramSha256::verify_client_proof(sk, auth_msg, good_proof));

    // Wrong proof (flip a byte)
    auto bad_proof = good_proof;
    bad_proof[0] ^= 0xFF;
    REQUIRE_FALSE(ScramSha256::verify_client_proof(sk, auth_msg, bad_proof));
}
