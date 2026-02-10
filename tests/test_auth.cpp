#include <catch2/catch_test_macros.hpp>
#include "server/http_server.hpp"
#include "config/config_loader.hpp"

using namespace sqlproxy;

// ============================================================================
// UserInfo tests
// ============================================================================

TEST_CASE("UserInfo default construction", "[auth]") {
    UserInfo info;
    CHECK(info.name.empty());
    CHECK(info.roles.empty());
    CHECK(info.api_key.empty());
    CHECK(info.attributes.empty());
}

TEST_CASE("UserInfo 2-arg constructor", "[auth]") {
    UserInfo info("alice", {"admin", "user"});
    CHECK(info.name == "alice");
    CHECK(info.roles.size() == 2);
    CHECK(info.api_key.empty());
}

TEST_CASE("UserInfo 3-arg constructor with API key", "[auth]") {
    UserInfo info("bob", {"analyst"}, "sk-test-key-123");
    CHECK(info.name == "bob");
    CHECK(info.roles.size() == 1);
    CHECK(info.api_key == "sk-test-key-123");
}

TEST_CASE("UserInfo attributes", "[auth]") {
    UserInfo info("carol", {"analyst"}, "sk-key");
    info.attributes["department"] = "analytics";
    info.attributes["region"] = "us-west";

    CHECK(info.attributes.size() == 2);
    CHECK(info.attributes["department"] == "analytics");
    CHECK(info.attributes["region"] == "us-west");
}

// ============================================================================
// ConfigLoader: parse users with api_key and attributes
// ============================================================================

TEST_CASE("ConfigLoader parses api_key from TOML", "[auth][config]") {
    std::string toml = R"(
[[users]]
name = "admin"
roles = ["admin"]
api_key = "sk-admin-key-12345"

[[users]]
name = "analyst"
roles = ["analyst", "readonly"]
api_key = "sk-analyst-key-67890"
attributes = {department = "analytics", region = "us-west"}

[[users]]
name = "nokey"
roles = ["user"]

[[policies]]
name = "allow_all"
priority = 1
action = "ALLOW"
users = ["*"]
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);

    const auto& users = result.config.users;
    REQUIRE(users.size() == 3);

    // Admin with API key
    auto admin_it = users.find("admin");
    REQUIRE(admin_it != users.end());
    CHECK(admin_it->second.api_key == "sk-admin-key-12345");
    CHECK(admin_it->second.attributes.empty());

    // Analyst with API key and attributes
    auto analyst_it = users.find("analyst");
    REQUIRE(analyst_it != users.end());
    CHECK(analyst_it->second.api_key == "sk-analyst-key-67890");
    CHECK(analyst_it->second.attributes.size() == 2);
    CHECK(analyst_it->second.attributes.at("department") == "analytics");
    CHECK(analyst_it->second.attributes.at("region") == "us-west");

    // User without API key
    auto nokey_it = users.find("nokey");
    REQUIRE(nokey_it != users.end());
    CHECK(nokey_it->second.api_key.empty());
}

// ============================================================================
// ConfigLoader: parse column policies with masking
// ============================================================================

TEST_CASE("ConfigLoader parses column-level policies", "[auth][config]") {
    std::string toml = R"(
[[policies]]
name = "block_ssn"
priority = 95
action = "BLOCK"
roles = ["analyst"]
database = "testdb"
table = "sensitive_data"
columns = ["ssn"]
reason = "SSN blocked"

[[policies]]
name = "mask_email"
priority = 90
action = "ALLOW"
roles = ["developer"]
database = "testdb"
schema = "public"
table = "customers"
columns = ["email"]
masking_action = "partial"
masking_prefix_len = 3
masking_suffix_len = 4
reason = "Email masked for devs"

[[policies]]
name = "allow_all"
priority = 1
action = "ALLOW"
users = ["*"]
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    REQUIRE(result.config.policies.size() == 3);

    // block_ssn
    const auto& p1 = result.config.policies[0];
    CHECK(p1.name == "block_ssn");
    CHECK(p1.action == Decision::BLOCK);
    REQUIRE(p1.scope.columns.size() == 1);
    CHECK(p1.scope.columns[0] == "ssn");

    // mask_email
    const auto& p2 = result.config.policies[1];
    CHECK(p2.name == "mask_email");
    CHECK(p2.action == Decision::ALLOW);
    REQUIRE(p2.scope.columns.size() == 1);
    CHECK(p2.scope.columns[0] == "email");
    CHECK(p2.masking_action == MaskingAction::PARTIAL);
    CHECK(p2.masking_prefix_len == 3);
    CHECK(p2.masking_suffix_len == 4);
}

// ============================================================================
// ConfigLoader: parse RLS and rewrite rules
// ============================================================================

TEST_CASE("ConfigLoader parses RLS rules", "[auth][config]") {
    std::string toml = R"(
[[policies]]
name = "allow_all"
priority = 1
action = "ALLOW"
users = ["*"]

[[row_level_security]]
name = "region_filter"
database = "testdb"
table = "customers"
condition = "region = '$ATTR.region'"
roles = ["analyst"]

[[row_level_security]]
name = "owner_filter"
table = "orders"
condition = "created_by = '$USER'"
users = ["developer"]
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    REQUIRE(result.config.rls_rules.size() == 2);

    CHECK(result.config.rls_rules[0].name == "region_filter");
    CHECK(result.config.rls_rules[0].database.value() == "testdb");
    CHECK(result.config.rls_rules[0].table.value() == "customers");
    CHECK(result.config.rls_rules[0].condition == "region = '$ATTR.region'");
    CHECK(result.config.rls_rules[0].roles.size() == 1);

    CHECK(result.config.rls_rules[1].name == "owner_filter");
    CHECK(!result.config.rls_rules[1].database.has_value());
    CHECK(result.config.rls_rules[1].table.value() == "orders");
}

TEST_CASE("ConfigLoader parses rewrite rules", "[auth][config]") {
    std::string toml = R"(
[[policies]]
name = "allow_all"
priority = 1
action = "ALLOW"
users = ["*"]

[[rewrite_rules]]
name = "enforce_limit"
type = "enforce_limit"
limit_value = 1000
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    REQUIRE(result.config.rewrite_rules.size() == 1);

    CHECK(result.config.rewrite_rules[0].name == "enforce_limit");
    CHECK(result.config.rewrite_rules[0].type == "enforce_limit");
    CHECK(result.config.rewrite_rules[0].limit_value == 1000);
}

// ============================================================================
// PolicyScope specificity with columns
// ============================================================================

TEST_CASE("PolicyScope specificity includes columns", "[auth]") {
    PolicyScope scope;
    CHECK(scope.specificity() == 0);  // Empty

    scope.database = "testdb";
    CHECK(scope.specificity() == 1);

    scope.schema = "public";
    CHECK(scope.specificity() == 3);  // db(1) | schema(2)

    scope.table = "customers";
    CHECK(scope.specificity() == 7);  // db(1) | schema(2) | table(4)

    scope.columns = {"email"};
    CHECK(scope.specificity() == 15);  // db(1) | schema(2) | table(4) | columns(8)

    // Column without table
    PolicyScope col_only;
    col_only.columns = {"ssn"};
    CHECK(col_only.specificity() == 8);  // columns(8) only
}
