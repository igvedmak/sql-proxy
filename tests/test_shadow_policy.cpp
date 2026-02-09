#include <catch2/catch_test_macros.hpp>
#include "policy/policy_engine.hpp"
#include "config/config_loader.hpp"
#include "core/types.hpp"

using namespace sqlproxy;

namespace {

Policy make_policy(const std::string& name, Decision action, const std::string& db,
                   const std::string& table, bool shadow = false, int priority = 10) {
    Policy p;
    p.name = name;
    p.action = action;
    p.priority = priority;
    p.shadow = shadow;
    p.scope.database = db;
    p.scope.table = table;
    p.users.insert("*");
    return p;
}

AnalysisResult make_analysis(const std::string& table, StatementType stmt = StatementType::SELECT) {
    AnalysisResult a;
    a.statement_type = stmt;
    TableRef ref;
    ref.table = table;
    a.source_tables.push_back(ref);
    return a;
}

} // anonymous namespace

TEST_CASE("Shadow policy - BLOCK is logged but not enforced", "[policy][shadow]") {
    PolicyEngine engine;

    std::vector<Policy> policies;
    policies.push_back(make_policy("allow_customers", Decision::ALLOW, "testdb", "customers", false));
    policies.push_back(make_policy("shadow_block_customers", Decision::BLOCK, "testdb", "customers", true));

    engine.load_policies(policies);

    auto analysis = make_analysis("customers");
    auto result = engine.evaluate("analyst", {"user"}, "testdb", analysis);

    // Enforcement: ALLOW (shadow doesn't block)
    REQUIRE(result.decision == Decision::ALLOW);

    // Shadow: would have blocked
    REQUIRE(result.shadow_blocked);
    REQUIRE(result.shadow_policy == "shadow_block_customers");
}

TEST_CASE("Shadow policy - enforcement BLOCK still blocks", "[policy][shadow]") {
    PolicyEngine engine;

    std::vector<Policy> policies;
    policies.push_back(make_policy("block_customers", Decision::BLOCK, "testdb", "customers", false));
    policies.push_back(make_policy("shadow_allow", Decision::ALLOW, "testdb", "customers", true));

    engine.load_policies(policies);

    auto analysis = make_analysis("customers");
    auto result = engine.evaluate("analyst", {"user"}, "testdb", analysis);

    // Enforcement BLOCK wins
    REQUIRE(result.decision == Decision::BLOCK);
}

TEST_CASE("Shadow policy - no shadow policies means no shadow flags", "[policy][shadow]") {
    PolicyEngine engine;

    std::vector<Policy> policies;
    policies.push_back(make_policy("allow_all", Decision::ALLOW, "testdb", "customers", false));

    engine.load_policies(policies);

    auto analysis = make_analysis("customers");
    auto result = engine.evaluate("analyst", {"user"}, "testdb", analysis);

    REQUIRE(result.decision == Decision::ALLOW);
    REQUIRE_FALSE(result.shadow_blocked);
    REQUIRE(result.shadow_policy.empty());
}

TEST_CASE("Shadow policy - shadow ALLOW doesn't set shadow_blocked", "[policy][shadow]") {
    PolicyEngine engine;

    std::vector<Policy> policies;
    policies.push_back(make_policy("allow_customers", Decision::ALLOW, "testdb", "customers", false));
    policies.push_back(make_policy("shadow_allow_too", Decision::ALLOW, "testdb", "customers", true));

    engine.load_policies(policies);

    auto analysis = make_analysis("customers");
    auto result = engine.evaluate("analyst", {"user"}, "testdb", analysis);

    REQUIRE(result.decision == Decision::ALLOW);
    REQUIRE_FALSE(result.shadow_blocked);
}

TEST_CASE("Policy shadow field in struct", "[policy][shadow]") {
    Policy p;
    REQUIRE_FALSE(p.shadow);  // Default is false

    p.shadow = true;
    REQUIRE(p.shadow);
}

TEST_CASE("Shadow policy parsed from TOML config", "[policy][shadow][config]") {
    std::string toml = R"(
[[policies]]
name = "shadow_strict"
action = "block"
shadow = true
database = "production"
table = "customers"
users = ["*"]
reason = "Testing stricter policy"
priority = 10
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    REQUIRE(result.config.policies.size() == 1);
    REQUIRE(result.config.policies[0].shadow);
    REQUIRE(result.config.policies[0].name == "shadow_strict");
}

TEST_CASE("Shadow defaults to false in TOML", "[policy][shadow][config]") {
    std::string toml = R"(
[[policies]]
name = "regular_allow"
action = "allow"
database = "testdb"
table = "customers"
users = ["*"]
priority = 10
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    REQUIRE(result.config.policies.size() == 1);
    REQUIRE_FALSE(result.config.policies[0].shadow);
}

TEST_CASE("Dry-run flag in ProxyRequest", "[policy][dryrun]") {
    ProxyRequest req;
    REQUIRE_FALSE(req.dry_run);

    req.dry_run = true;
    REQUIRE(req.dry_run);
}

TEST_CASE("AuditRecord has shadow fields", "[audit][shadow]") {
    AuditRecord record;
    REQUIRE_FALSE(record.shadow_blocked);
    REQUIRE(record.shadow_policy.empty());

    record.shadow_blocked = true;
    record.shadow_policy = "test_shadow";
    REQUIRE(record.shadow_blocked);
    REQUIRE(record.shadow_policy == "test_shadow");
}

TEST_CASE("AuditRecord has hash chain fields", "[audit][integrity]") {
    AuditRecord record;
    REQUIRE(record.record_hash.empty());
    REQUIRE(record.previous_hash.empty());

    record.record_hash = "abc123";
    record.previous_hash = "def456";
    REQUIRE(record.record_hash == "abc123");
}
