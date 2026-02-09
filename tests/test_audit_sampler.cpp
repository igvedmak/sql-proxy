#include <catch2/catch_test_macros.hpp>
#include "audit/audit_sampler.hpp"
#include "config/config_loader.hpp"

using namespace sqlproxy;

TEST_CASE("AuditSampler: disabled samples everything", "[audit][sampler]") {
    AuditSampler::Config cfg;
    cfg.enabled = false;
    AuditSampler sampler(cfg);

    CHECK(sampler.should_sample(StatementType::SELECT, Decision::ALLOW, ErrorCode::NONE, 12345));
    CHECK(sampler.should_sample(StatementType::INSERT, Decision::ALLOW, ErrorCode::NONE, 67890));

    auto stats = sampler.get_stats();
    CHECK(stats.total_checked == 2);
    CHECK(stats.total_sampled == 2);
    CHECK(stats.total_dropped == 0);
}

TEST_CASE("AuditSampler: always_log_blocked overrides rate", "[audit][sampler]") {
    AuditSampler::Config cfg;
    cfg.enabled = true;
    cfg.default_sample_rate = 0.0;  // Drop everything
    cfg.select_sample_rate = 0.0;
    cfg.always_log_blocked = true;
    AuditSampler sampler(cfg);

    CHECK(sampler.should_sample(StatementType::SELECT, Decision::BLOCK, ErrorCode::NONE, 100));
}

TEST_CASE("AuditSampler: always_log_writes overrides rate", "[audit][sampler]") {
    AuditSampler::Config cfg;
    cfg.enabled = true;
    cfg.default_sample_rate = 0.0;
    cfg.always_log_writes = true;
    AuditSampler sampler(cfg);

    CHECK(sampler.should_sample(StatementType::INSERT, Decision::ALLOW, ErrorCode::NONE, 100));
    CHECK(sampler.should_sample(StatementType::UPDATE, Decision::ALLOW, ErrorCode::NONE, 200));
    CHECK(sampler.should_sample(StatementType::DELETE, Decision::ALLOW, ErrorCode::NONE, 300));
}

TEST_CASE("AuditSampler: always_log_errors overrides rate", "[audit][sampler]") {
    AuditSampler::Config cfg;
    cfg.enabled = true;
    cfg.default_sample_rate = 0.0;
    cfg.select_sample_rate = 0.0;
    cfg.always_log_errors = true;
    AuditSampler sampler(cfg);

    CHECK(sampler.should_sample(StatementType::SELECT, Decision::ALLOW, ErrorCode::PARSE_ERROR, 100));
}

TEST_CASE("AuditSampler: select_sample_rate=0 drops all SELECTs", "[audit][sampler]") {
    AuditSampler::Config cfg;
    cfg.enabled = true;
    cfg.default_sample_rate = 1.0;
    cfg.select_sample_rate = 0.0;
    cfg.always_log_blocked = false;
    cfg.always_log_writes = false;
    cfg.always_log_errors = false;
    cfg.deterministic = true;
    AuditSampler sampler(cfg);

    for (int i = 0; i < 100; ++i) {
        CHECK_FALSE(sampler.should_sample(StatementType::SELECT, Decision::ALLOW, ErrorCode::NONE, i));
    }
}

TEST_CASE("AuditSampler: select_sample_rate=1 keeps all SELECTs", "[audit][sampler]") {
    AuditSampler::Config cfg;
    cfg.enabled = true;
    cfg.select_sample_rate = 1.0;
    cfg.deterministic = true;
    AuditSampler sampler(cfg);

    for (int i = 0; i < 100; ++i) {
        CHECK(sampler.should_sample(StatementType::SELECT, Decision::ALLOW, ErrorCode::NONE, i));
    }
}

TEST_CASE("AuditSampler: deterministic gives consistent decisions", "[audit][sampler]") {
    AuditSampler::Config cfg;
    cfg.enabled = true;
    cfg.select_sample_rate = 0.5;  // 50%
    cfg.deterministic = true;
    AuditSampler sampler(cfg);

    // Same fingerprint should always produce same result
    bool result1 = sampler.should_sample(StatementType::SELECT, Decision::ALLOW, ErrorCode::NONE, 42);
    bool result2 = sampler.should_sample(StatementType::SELECT, Decision::ALLOW, ErrorCode::NONE, 42);
    CHECK(result1 == result2);
}

TEST_CASE("AuditSampler: stats tracking", "[audit][sampler]") {
    AuditSampler::Config cfg;
    cfg.enabled = true;
    cfg.default_sample_rate = 1.0;
    cfg.select_sample_rate = 0.0;
    cfg.always_log_blocked = false;
    cfg.always_log_writes = false;
    cfg.always_log_errors = false;
    cfg.deterministic = true;
    AuditSampler sampler(cfg);

    // SELECT with rate=0 → dropped
    (void)sampler.should_sample(StatementType::SELECT, Decision::ALLOW, ErrorCode::NONE, 1);
    // INSERT with rate=1 → sampled
    (void)sampler.should_sample(StatementType::INSERT, Decision::ALLOW, ErrorCode::NONE, 2);

    auto stats = sampler.get_stats();
    CHECK(stats.total_checked == 2);
    CHECK(stats.total_sampled == 1);
    CHECK(stats.total_dropped == 1);
}

TEST_CASE("AuditSampler: config from TOML", "[audit][sampler][config]") {
    std::string toml = R"(
[audit.sampling]
enabled = true
default_sample_rate = 0.8
select_sample_rate = 0.1
always_log_blocked = true
always_log_writes = false
always_log_errors = true
deterministic = true
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    REQUIRE(result.config.audit_sampling.enabled);
    REQUIRE(result.config.audit_sampling.default_sample_rate == 0.8);
    REQUIRE(result.config.audit_sampling.select_sample_rate == 0.1);
    REQUIRE(result.config.audit_sampling.always_log_blocked == true);
    REQUIRE(result.config.audit_sampling.always_log_writes == false);
    REQUIRE(result.config.audit_sampling.always_log_errors == true);
    REQUIRE(result.config.audit_sampling.deterministic == true);
}
