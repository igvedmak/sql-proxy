#include <catch2/catch_test_macros.hpp>
#include "security/env_key_manager.hpp"
#include "security/vault_key_manager.hpp"
#include "config/config_loader.hpp"

#include <cstdlib>

using namespace sqlproxy;

// ============================================================================
// EnvKeyManager Tests
// ============================================================================

TEST_CASE("EnvKeyManager - loads key from env variable", "[security][keymanager]") {
    // Set test environment variable (hex-encoded 32-byte key)
    std::string hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    setenv("TEST_ENC_KEY", hex_key.c_str(), 1);

    EnvKeyManager mgr("TEST_ENC_KEY");

    auto key = mgr.get_active_key();
    REQUIRE(key.has_value());
    REQUIRE(key->key_id == "env-key-1");
    REQUIRE(key->key_bytes.size() == 32);
    REQUIRE(key->active);
    REQUIRE(mgr.key_count() == 1);

    // Verify hex decode
    REQUIRE(key->key_bytes[0] == 0x01);
    REQUIRE(key->key_bytes[1] == 0x23);

    unsetenv("TEST_ENC_KEY");
}

TEST_CASE("EnvKeyManager - missing env variable", "[security][keymanager]") {
    unsetenv("NONEXISTENT_KEY_VAR");
    EnvKeyManager mgr("NONEXISTENT_KEY_VAR");

    auto key = mgr.get_active_key();
    REQUIRE_FALSE(key.has_value());
    REQUIRE(mgr.key_count() == 0);
}

TEST_CASE("EnvKeyManager - get_key by ID", "[security][keymanager]") {
    setenv("TEST_ENC_KEY2", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1);
    EnvKeyManager mgr("TEST_ENC_KEY2");

    auto key = mgr.get_key("env-key-1");
    REQUIRE(key.has_value());

    auto bad = mgr.get_key("nonexistent-key");
    REQUIRE_FALSE(bad.has_value());

    unsetenv("TEST_ENC_KEY2");
}

TEST_CASE("EnvKeyManager - rotation not supported", "[security][keymanager]") {
    setenv("TEST_ENC_KEY3", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1);
    EnvKeyManager mgr("TEST_ENC_KEY3");

    REQUIRE_FALSE(mgr.rotate_key());

    unsetenv("TEST_ENC_KEY3");
}

// ============================================================================
// VaultKeyManager Tests (without actual Vault server)
// ============================================================================

TEST_CASE("VaultKeyManager - creation with empty addr", "[security][keymanager][vault]") {
    VaultKeyManagerConfig config;
    config.vault_addr = "";  // No Vault server
    config.vault_token = "test-token";

    VaultKeyManager mgr(config);

    // Should handle gracefully without crashing
    auto key = mgr.get_active_key();
    REQUIRE_FALSE(key.has_value());
    REQUIRE(mgr.key_count() == 0);
}

// ============================================================================
// Config Parsing
// ============================================================================

TEST_CASE("Key manager config parsed from TOML", "[security][keymanager][config]") {
    std::string toml = R"(
[encryption]
enabled = true

[encryption.key_manager]
provider = "vault"
vault_addr = "https://vault.internal:8200"
vault_token = "s.abcdef123456"
vault_key_name = "prod-key"
vault_mount = "transit"
vault_cache_ttl_seconds = 600
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    REQUIRE(result.config.encryption.key_manager_provider == "vault");
    REQUIRE(result.config.encryption.vault_addr == "https://vault.internal:8200");
    REQUIRE(result.config.encryption.vault_token == "s.abcdef123456");
    REQUIRE(result.config.encryption.vault_key_name == "prod-key");
    REQUIRE(result.config.encryption.vault_cache_ttl_seconds == 600);
}

TEST_CASE("Key manager defaults to local", "[security][keymanager][config]") {
    std::string toml = R"(
[encryption]
enabled = true
key_file = "config/keys.json"
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    REQUIRE(result.config.encryption.key_manager_provider == "local");
}

TEST_CASE("Env key manager config from TOML", "[security][keymanager][config]") {
    std::string toml = R"(
[encryption]
enabled = true

[encryption.key_manager]
provider = "env"
env_key_var = "MY_SECRET_KEY"
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    REQUIRE(result.config.encryption.key_manager_provider == "env");
    REQUIRE(result.config.encryption.env_key_var == "MY_SECRET_KEY");
}
