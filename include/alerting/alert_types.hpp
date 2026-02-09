#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/utils.hpp"

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
    AlertCondition condition = AlertCondition::CUSTOM_METRIC;
    std::string severity;
    double current_value = 0.0;
    double threshold = 0.0;
    std::string message;
    std::chrono::system_clock::time_point fired_at;
    bool resolved = false;

    Alert()
        : id(utils::generate_uuid()),
          fired_at(std::chrono::system_clock::now()) {}
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
    static const std::unordered_map<std::string, AlertCondition> lookup = {
        {"rate_limit_breach",      AlertCondition::RATE_LIMIT_BREACH},
        {"policy_violation_spike", AlertCondition::POLICY_VIOLATION_SPIKE},
        {"circuit_breaker_open",   AlertCondition::CIRCUIT_BREAKER_OPEN},
        {"pii_exposure_spike",     AlertCondition::PII_EXPOSURE_SPIKE},
        {"audit_buffer_overflow",  AlertCondition::AUDIT_BUFFER_OVERFLOW},
    };
    const auto it = lookup.find(s);
    return (it != lookup.end()) ? it->second : AlertCondition::CUSTOM_METRIC;
}

} // namespace sqlproxy
