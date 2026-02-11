#include <catch2/catch_test_macros.hpp>
#include "tenant/data_residency.hpp"

using namespace sqlproxy;

TEST_CASE("DataResidencyEnforcer - disabled", "[data_residency]") {
    DataResidencyEnforcer enforcer;
    REQUIRE_FALSE(enforcer.is_enabled());

    auto result = enforcer.check("tenant1", "testdb");
    REQUIRE(result.allowed);
}

TEST_CASE("DataResidencyEnforcer - no rules allows by default", "[data_residency]") {
    DataResidencyEnforcer::Config cfg;
    cfg.enabled = true;
    DataResidencyEnforcer enforcer(cfg);

    enforcer.set_database_region("testdb", "us-east");

    auto result = enforcer.check("tenant1", "testdb");
    REQUIRE(result.allowed);
    REQUIRE(result.database_region == "us-east");
}

TEST_CASE("DataResidencyEnforcer - allow matching region", "[data_residency]") {
    DataResidencyEnforcer::Config cfg;
    cfg.enabled = true;
    DataResidencyEnforcer enforcer(cfg);

    enforcer.set_database_region("testdb", "us-east");
    enforcer.set_tenant_rules("acme", {"us-east", "us-west"});

    auto result = enforcer.check("acme", "testdb");
    REQUIRE(result.allowed);
    REQUIRE(result.database_region == "us-east");
    REQUIRE(result.reason.empty());
}

TEST_CASE("DataResidencyEnforcer - block mismatched region", "[data_residency]") {
    DataResidencyEnforcer::Config cfg;
    cfg.enabled = true;
    DataResidencyEnforcer enforcer(cfg);

    enforcer.set_database_region("testdb", "us-east");
    enforcer.set_database_region("eu-db", "eu-west");
    enforcer.set_tenant_rules("eu-only", {"eu-west", "eu-central"});

    // EU tenant accessing US database
    auto result = enforcer.check("eu-only", "testdb");
    REQUIRE_FALSE(result.allowed);
    REQUIRE(result.database_region == "us-east");
    REQUIRE(result.reason.find("residency violation") != std::string::npos);

    // EU tenant accessing EU database
    auto result2 = enforcer.check("eu-only", "eu-db");
    REQUIRE(result2.allowed);
}

TEST_CASE("DataResidencyEnforcer - unknown database", "[data_residency]") {
    DataResidencyEnforcer::Config cfg;
    cfg.enabled = true;
    DataResidencyEnforcer enforcer(cfg);

    enforcer.set_tenant_rules("acme", {"us-east"});

    auto result = enforcer.check("acme", "unknown-db");
    REQUIRE(result.allowed);  // No region info = allow
}

TEST_CASE("DataResidencyEnforcer - counts", "[data_residency]") {
    DataResidencyEnforcer::Config cfg;
    cfg.enabled = true;
    DataResidencyEnforcer enforcer(cfg);

    enforcer.set_database_region("db1", "us-east");
    enforcer.set_database_region("db2", "eu-west");
    enforcer.set_tenant_rules("t1", {"us-east"});
    enforcer.set_tenant_rules("t2", {"eu-west"});

    REQUIRE(enforcer.database_count() == 2);
    REQUIRE(enforcer.tenant_rule_count() == 2);
}
