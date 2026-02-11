#include <catch2/catch_test_macros.hpp>
#include "security/sql_firewall.hpp"

using namespace sqlproxy;

TEST_CASE("SqlFirewall disabled mode allows everything", "[firewall]") {
    SqlFirewall::Config cfg;
    cfg.enabled = true;
    cfg.initial_mode = FirewallMode::DISABLED;
    SqlFirewall fw(cfg);

    auto result = fw.check(12345);
    REQUIRE(result.allowed);
    REQUIRE_FALSE(result.is_new_fingerprint);
}

TEST_CASE("SqlFirewall learning mode records fingerprints", "[firewall]") {
    SqlFirewall::Config cfg;
    cfg.enabled = true;
    cfg.initial_mode = FirewallMode::LEARNING;
    SqlFirewall fw(cfg);

    REQUIRE(fw.allowlist_size() == 0);

    auto r1 = fw.check(100);
    REQUIRE(r1.allowed);
    REQUIRE(r1.is_new_fingerprint);

    fw.record(100);
    REQUIRE(fw.allowlist_size() == 1);

    auto r2 = fw.check(100);
    REQUIRE(r2.allowed);
    REQUIRE_FALSE(r2.is_new_fingerprint);
}

TEST_CASE("SqlFirewall enforcing mode blocks unknown fingerprints", "[firewall]") {
    SqlFirewall::Config cfg;
    cfg.enabled = true;
    cfg.initial_mode = FirewallMode::LEARNING;
    SqlFirewall fw(cfg);

    // Learn some fingerprints
    fw.record(100);
    fw.record(200);
    fw.record(300);
    REQUIRE(fw.allowlist_size() == 3);

    // Switch to enforcing
    fw.set_mode(FirewallMode::ENFORCING);
    REQUIRE(fw.mode() == FirewallMode::ENFORCING);

    // Known fingerprints allowed
    auto r1 = fw.check(100);
    REQUIRE(r1.allowed);
    REQUIRE_FALSE(r1.is_new_fingerprint);

    // Unknown fingerprint blocked
    auto r2 = fw.check(999);
    REQUIRE_FALSE(r2.allowed);
    REQUIRE(r2.is_new_fingerprint);
}

TEST_CASE("SqlFirewall mode transitions", "[firewall]") {
    SqlFirewall::Config cfg;
    cfg.enabled = true;
    cfg.initial_mode = FirewallMode::DISABLED;
    SqlFirewall fw(cfg);

    REQUIRE(fw.mode() == FirewallMode::DISABLED);

    fw.set_mode(FirewallMode::LEARNING);
    REQUIRE(fw.mode() == FirewallMode::LEARNING);

    fw.record(42);
    REQUIRE(fw.allowlist_size() == 1);

    fw.set_mode(FirewallMode::ENFORCING);
    REQUIRE(fw.mode() == FirewallMode::ENFORCING);

    // Record should be ignored in enforcing mode
    fw.record(999);
    REQUIRE(fw.allowlist_size() == 1);
}

TEST_CASE("SqlFirewall get_allowlist returns all fingerprints", "[firewall]") {
    SqlFirewall::Config cfg;
    cfg.enabled = true;
    cfg.initial_mode = FirewallMode::LEARNING;
    SqlFirewall fw(cfg);

    fw.record(10);
    fw.record(20);
    fw.record(30);

    auto list = fw.get_allowlist();
    REQUIRE(list.size() == 3);
}
