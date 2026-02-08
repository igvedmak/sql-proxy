#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace sqlproxy {

enum class AlertCondition {
    RATE_LIMIT_BREACH,
    POLICY_VIOLATION_SPIKE,
    CIRCUIT_BREAKER_OPEN,
    PII_EXPOSURE_SPIKE,
    AUDIT_BUFFER_OVERFLOW,
    CUSTOM_METRIC
};

struct AlertRule {
    std::string name;
    AlertCondition condition = AlertCondition::CUSTOM_METRIC;
    double threshold = 0.0;
    std::chrono::seconds window{60};
    std::chrono::seconds cooldown{300};
    std::string severity = "warning";
    bool enabled = true;
};

struct Alert {
    std::string id;
    std::string rule_name;
    AlertCondition condition;
    std::string severity;
    double current_value = 0.0;
    double threshold = 0.0;
    std::string message;
    std::chrono::system_clock::time_point fired_at;
    bool resolved = false;
};

struct AlertWebhookConfig {
    bool enabled = false;
    std::string url;
    std::string auth_header;
};

struct AlertingConfig {
    bool enabled = false;
    int evaluation_interval_seconds = 10;
    std::vector<AlertRule> rules;
    AlertWebhookConfig webhook;
    std::string alert_log_file = "alerts.jsonl";
};

[[nodiscard]] inline std::string alert_condition_to_string(AlertCondition c) {
    switch (c) {
        case AlertCondition::RATE_LIMIT_BREACH: return "rate_limit_breach";
        case AlertCondition::POLICY_VIOLATION_SPIKE: return "policy_violation_spike";
        case AlertCondition::CIRCUIT_BREAKER_OPEN: return "circuit_breaker_open";
        case AlertCondition::PII_EXPOSURE_SPIKE: return "pii_exposure_spike";
        case AlertCondition::AUDIT_BUFFER_OVERFLOW: return "audit_buffer_overflow";
        case AlertCondition::CUSTOM_METRIC: return "custom_metric";
    }
    return "unknown";
}

[[nodiscard]] inline AlertCondition parse_alert_condition(const std::string& s) {
    if (s == "rate_limit_breach") return AlertCondition::RATE_LIMIT_BREACH;
    if (s == "policy_violation_spike") return AlertCondition::POLICY_VIOLATION_SPIKE;
    if (s == "circuit_breaker_open") return AlertCondition::CIRCUIT_BREAKER_OPEN;
    if (s == "pii_exposure_spike") return AlertCondition::PII_EXPOSURE_SPIKE;
    if (s == "audit_buffer_overflow") return AlertCondition::AUDIT_BUFFER_OVERFLOW;
    return AlertCondition::CUSTOM_METRIC;
}

} // namespace sqlproxy
