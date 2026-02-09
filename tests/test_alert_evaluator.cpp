#include <catch2/catch_test_macros.hpp>
#include "alerting/alert_evaluator.hpp"
#include "alerting/alert_types.hpp"
#include "server/rate_limiter.hpp"

#include <filesystem>
#include <fstream>
#include <thread>

using namespace sqlproxy;

namespace {


} // anonymous namespace

// ============================================================================
// AlertCondition / AlertRule Tests
// ============================================================================

TEST_CASE("Alerting: alert_condition_to_string", "[alerting]") {
    REQUIRE(alert_condition_to_string(AlertCondition::RATE_LIMIT_BREACH) == "rate_limit_breach");
    REQUIRE(alert_condition_to_string(AlertCondition::POLICY_VIOLATION_SPIKE) == "policy_violation_spike");
    REQUIRE(alert_condition_to_string(AlertCondition::CIRCUIT_BREAKER_OPEN) == "circuit_breaker_open");
    REQUIRE(alert_condition_to_string(AlertCondition::PII_EXPOSURE_SPIKE) == "pii_exposure_spike");
    REQUIRE(alert_condition_to_string(AlertCondition::AUDIT_BUFFER_OVERFLOW) == "audit_buffer_overflow");
    REQUIRE(alert_condition_to_string(AlertCondition::CUSTOM_METRIC) == "custom_metric");
}

TEST_CASE("Alerting: parse_alert_condition", "[alerting]") {
    REQUIRE(parse_alert_condition("rate_limit_breach") == AlertCondition::RATE_LIMIT_BREACH);
    REQUIRE(parse_alert_condition("policy_violation_spike") == AlertCondition::POLICY_VIOLATION_SPIKE);
    REQUIRE(parse_alert_condition("circuit_breaker_open") == AlertCondition::CIRCUIT_BREAKER_OPEN);
    REQUIRE(parse_alert_condition("pii_exposure_spike") == AlertCondition::PII_EXPOSURE_SPIKE);
    REQUIRE(parse_alert_condition("audit_buffer_overflow") == AlertCondition::AUDIT_BUFFER_OVERFLOW);
    REQUIRE(parse_alert_condition("unknown_thing") == AlertCondition::CUSTOM_METRIC);
}

TEST_CASE("Alerting: AlertRule defaults", "[alerting]") {
    AlertRule rule;
    REQUIRE(rule.threshold == 0.0);
    REQUIRE(rule.window == std::chrono::seconds(60));
    REQUIRE(rule.cooldown == std::chrono::seconds(300));
    REQUIRE(rule.severity == "warning");
    REQUIRE(rule.enabled);
}

TEST_CASE("Alerting: AlertingConfig defaults", "[alerting]") {
    AlertingConfig config;
    REQUIRE_FALSE(config.enabled);
    REQUIRE(config.evaluation_interval_seconds == 10);
    REQUIRE(config.rules.empty());
    REQUIRE_FALSE(config.webhook.enabled);
    REQUIRE(config.alert_log_file == "alerts.jsonl");
}

// ============================================================================
// AlertEvaluator Tests
// ============================================================================

TEST_CASE("Alerting: evaluator start and stop", "[alerting]") {
    std::string audit_file = "/tmp/test_alert_eval_audit.jsonl";
    std::string alert_log = "/tmp/test_alert_eval_log.jsonl";
    std::filesystem::remove(audit_file);
    std::filesystem::remove(alert_log);

    auto audit = std::make_shared<AuditEmitter>(audit_file);
    HierarchicalRateLimiter::Config rl_config;
    auto rate_limiter = std::make_shared<HierarchicalRateLimiter>(rl_config);

    AlertingConfig config;
    config.enabled = true;
    config.evaluation_interval_seconds = 1;
    config.alert_log_file = alert_log;

    AlertEvaluator evaluator(config, audit, rate_limiter);
    evaluator.start();

    auto stats = evaluator.get_stats();
    REQUIRE(stats.active_alert_count == 0);

    evaluator.stop();

    std::filesystem::remove(audit_file);
    std::filesystem::remove(alert_log);
}

TEST_CASE("Alerting: evaluator disabled does not start thread", "[alerting]") {
    std::string audit_file = "/tmp/test_alert_disabled.jsonl";
    std::filesystem::remove(audit_file);

    auto audit = std::make_shared<AuditEmitter>(audit_file);
    HierarchicalRateLimiter::Config rl_config;
    auto rate_limiter = std::make_shared<HierarchicalRateLimiter>(rl_config);

    AlertingConfig config;
    config.enabled = false;

    AlertEvaluator evaluator(config, audit, rate_limiter);
    evaluator.start();  // Should be a no-op

    auto stats = evaluator.get_stats();
    REQUIRE(stats.evaluations == 0);

    evaluator.stop();
    std::filesystem::remove(audit_file);
}

TEST_CASE("Alerting: evaluator performs evaluations", "[alerting]") {
    std::string audit_file = "/tmp/test_alert_eval_run.jsonl";
    std::string alert_log = "/tmp/test_alert_eval_run_log.jsonl";
    std::filesystem::remove(audit_file);
    std::filesystem::remove(alert_log);

    auto audit = std::make_shared<AuditEmitter>(audit_file);
    HierarchicalRateLimiter::Config rl_config;
    auto rate_limiter = std::make_shared<HierarchicalRateLimiter>(rl_config);

    AlertingConfig config;
    config.enabled = true;
    config.evaluation_interval_seconds = 1;
    config.alert_log_file = alert_log;

    AlertRule rule;
    rule.name = "test_rule";
    rule.condition = AlertCondition::RATE_LIMIT_BREACH;
    rule.threshold = 999999;  // Very high - shouldn't fire
    rule.cooldown = std::chrono::seconds(1);
    config.rules.push_back(rule);

    AlertEvaluator evaluator(config, audit, rate_limiter);
    evaluator.start();

    // Wait for at least one evaluation
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));

    auto stats = evaluator.get_stats();
    REQUIRE(stats.evaluations >= 1);
    REQUIRE(stats.active_alert_count == 0);  // Threshold too high to fire
    REQUIRE(stats.rule_count == 1);

    evaluator.stop();

    std::filesystem::remove(audit_file);
    std::filesystem::remove(alert_log);
}

TEST_CASE("Alerting: hot reload rules", "[alerting]") {
    std::string audit_file = "/tmp/test_alert_reload.jsonl";
    std::filesystem::remove(audit_file);

    auto audit = std::make_shared<AuditEmitter>(audit_file);
    HierarchicalRateLimiter::Config rl_config;
    auto rate_limiter = std::make_shared<HierarchicalRateLimiter>(rl_config);

    AlertingConfig config;
    config.enabled = true;
    config.evaluation_interval_seconds = 60;  // Long interval, we won't wait

    AlertRule rule1;
    rule1.name = "rule_1";
    config.rules.push_back(rule1);

    AlertEvaluator evaluator(config, audit, rate_limiter);

    auto stats = evaluator.get_stats();
    REQUIRE(stats.rule_count == 1);

    // Hot reload with 3 rules
    std::vector<AlertRule> new_rules;
    new_rules.push_back(AlertRule{.name = "r1"});
    new_rules.push_back(AlertRule{.name = "r2"});
    new_rules.push_back(AlertRule{.name = "r3"});
    evaluator.reload_rules(new_rules);

    stats = evaluator.get_stats();
    REQUIRE(stats.rule_count == 3);

    evaluator.stop();
    std::filesystem::remove(audit_file);
}

TEST_CASE("Alerting: active alerts and history", "[alerting]") {
    std::string audit_file = "/tmp/test_alert_history.jsonl";
    std::filesystem::remove(audit_file);

    auto audit = std::make_shared<AuditEmitter>(audit_file);
    HierarchicalRateLimiter::Config rl_config;
    auto rate_limiter = std::make_shared<HierarchicalRateLimiter>(rl_config);

    AlertingConfig config;
    config.enabled = false;

    AlertEvaluator evaluator(config, audit, rate_limiter);

    auto active = evaluator.active_alerts();
    REQUIRE(active.empty());

    auto history = evaluator.alert_history();
    REQUIRE(history.empty());

    evaluator.stop();
    std::filesystem::remove(audit_file);
}

TEST_CASE("Alerting: config parsing integration", "[alerting][config]") {
    AlertingConfig config;
    config.enabled = true;
    config.evaluation_interval_seconds = 15;

    AlertRule rule;
    rule.name = "test_overflow";
    rule.condition = AlertCondition::AUDIT_BUFFER_OVERFLOW;
    rule.threshold = 5.0;
    rule.window = std::chrono::seconds(30);
    rule.cooldown = std::chrono::seconds(120);
    rule.severity = "critical";
    config.rules.push_back(rule);

    config.webhook.enabled = true;
    config.webhook.url = "https://example.com/hook";
    config.webhook.auth_header = "Bearer token123";

    REQUIRE(config.enabled);
    REQUIRE(config.rules.size() == 1);
    REQUIRE(config.rules[0].name == "test_overflow");
    REQUIRE(config.rules[0].severity == "critical");
    REQUIRE(config.webhook.enabled);
    REQUIRE(config.webhook.url == "https://example.com/hook");
}
