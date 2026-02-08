#include <catch2/catch_test_macros.hpp>
#include "security/column_encryptor.hpp"
#include "security/ikey_manager.hpp"

#include <random>

using namespace sqlproxy;

// ============================================================================
// Mock key manager for testing (no file I/O)
// ============================================================================

class MockKeyManager : public IKeyManager {
public:
    MockKeyManager() {
        // Generate a deterministic test key
        key_.key_id = "test-key-001";
        key_.key_bytes.resize(32);
        std::mt19937 rng(42);  // Fixed seed for reproducibility
        for (auto& b : key_.key_bytes) {
            b = static_cast<uint8_t>(rng() & 0xFF);
        }
        key_.active = true;
    }

    std::optional<KeyInfo> get_active_key() const override { return key_; }
    std::optional<KeyInfo> get_key(const std::string& key_id) const override {
        if (key_id == key_.key_id) return key_;
        return std::nullopt;
    }
    bool rotate_key() override { return false; }
    size_t key_count() const override { return 1; }

private:
    KeyInfo key_;
};

// ============================================================================
// Encrypt/decrypt round-trip
// ============================================================================

TEST_CASE("Encrypt and decrypt round-trip produces original", "[encryptor]") {
    auto km = std::make_shared<MockKeyManager>();
    ColumnEncryptor::Config cfg;
    cfg.enabled = true;
    ColumnEncryptor enc(km, cfg);

    std::string plaintext = "hello world secret data";
    auto ciphertext = enc.encrypt(plaintext);

    // Ciphertext should be different from plaintext
    CHECK(ciphertext != plaintext);
    // Ciphertext should have ENC:v1: prefix
    CHECK(ciphertext.substr(0, 7) == "ENC:v1:");

    auto decrypted = enc.decrypt(ciphertext);
    CHECK(decrypted == plaintext);
}

TEST_CASE("Encrypt empty string round-trip", "[encryptor]") {
    auto km = std::make_shared<MockKeyManager>();
    ColumnEncryptor::Config cfg;
    cfg.enabled = true;
    ColumnEncryptor enc(km, cfg);

    auto ciphertext = enc.encrypt("");
    auto decrypted = enc.decrypt(ciphertext);
    CHECK(decrypted.empty());
}

TEST_CASE("Encrypt long string round-trip", "[encryptor]") {
    auto km = std::make_shared<MockKeyManager>();
    ColumnEncryptor::Config cfg;
    cfg.enabled = true;
    ColumnEncryptor enc(km, cfg);

    std::string plaintext(1000, 'x');
    auto ciphertext = enc.encrypt(plaintext);
    auto decrypted = enc.decrypt(ciphertext);
    CHECK(decrypted == plaintext);
}

// ============================================================================
// Each encryption produces different ciphertext (random IV)
// ============================================================================

TEST_CASE("Same plaintext produces different ciphertext each time", "[encryptor]") {
    auto km = std::make_shared<MockKeyManager>();
    ColumnEncryptor::Config cfg;
    cfg.enabled = true;
    ColumnEncryptor enc(km, cfg);

    auto ct1 = enc.encrypt("test data");
    auto ct2 = enc.encrypt("test data");
    CHECK(ct1 != ct2);  // Different IVs

    // But both decrypt to the same value
    CHECK(enc.decrypt(ct1) == "test data");
    CHECK(enc.decrypt(ct2) == "test data");
}

// ============================================================================
// Non-encrypted data passes through decrypt
// ============================================================================

TEST_CASE("Non-encrypted data passes through decrypt unchanged", "[encryptor]") {
    auto km = std::make_shared<MockKeyManager>();
    ColumnEncryptor::Config cfg;
    cfg.enabled = true;
    ColumnEncryptor enc(km, cfg);

    CHECK(enc.decrypt("plain text") == "plain text");
    CHECK(enc.decrypt("123-456-7890") == "123-456-7890");
    CHECK(enc.decrypt("") == "");
}

// ============================================================================
// Column encryption lookup
// ============================================================================

TEST_CASE("is_encrypted_column checks configured columns", "[encryptor]") {
    auto km = std::make_shared<MockKeyManager>();
    ColumnEncryptor::Config cfg;
    cfg.enabled = true;
    cfg.columns.push_back({"testdb", "sensitive_data", "ssn"});
    cfg.columns.push_back({"testdb", "customers", "credit_card"});
    ColumnEncryptor enc(km, cfg);

    CHECK(enc.is_encrypted_column("testdb", "sensitive_data", "ssn"));
    CHECK(enc.is_encrypted_column("testdb", "customers", "credit_card"));
    CHECK_FALSE(enc.is_encrypted_column("testdb", "customers", "name"));
    CHECK_FALSE(enc.is_encrypted_column("other_db", "sensitive_data", "ssn"));
}

// ============================================================================
// decrypt_result on query result
// ============================================================================

TEST_CASE("decrypt_result decrypts encrypted columns in query result", "[encryptor]") {
    auto km = std::make_shared<MockKeyManager>();
    ColumnEncryptor::Config cfg;
    cfg.enabled = true;
    cfg.columns.push_back({"testdb", "sensitive_data", "ssn"});
    ColumnEncryptor enc(km, cfg);

    // Encrypt a value
    std::string encrypted_ssn = enc.encrypt("123-45-6789");

    // Build a query result with the encrypted value
    QueryResult result;
    result.success = true;
    result.column_names = {"id", "ssn", "name"};
    result.rows = {
        {"1", encrypted_ssn, "Alice"},
        {"2", "plain-value", "Bob"},  // Not encrypted
    };

    // Build analysis with table reference
    AnalysisResult analysis;
    analysis.source_tables.push_back({"public", "sensitive_data"});

    enc.decrypt_result(result, "testdb", analysis);

    CHECK(result.rows[0][1] == "123-45-6789");  // Decrypted
    CHECK(result.rows[1][1] == "plain-value");   // Passthrough (not ENC: prefix)
}

// ============================================================================
// Ciphertext format validation
// ============================================================================

TEST_CASE("Encrypted ciphertext format is ENC:v1:<key_id>:<base64>", "[encryptor]") {
    auto km = std::make_shared<MockKeyManager>();
    ColumnEncryptor::Config cfg;
    cfg.enabled = true;
    ColumnEncryptor enc(km, cfg);

    auto ct = enc.encrypt("test");
    CHECK(ct.substr(0, 7) == "ENC:v1:");

    // Should contain key_id after prefix
    auto rest = ct.substr(7);
    auto colon_pos = rest.find(':');
    REQUIRE(colon_pos != std::string::npos);
    CHECK(rest.substr(0, colon_pos) == "test-key-001");
}
