#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/utils.hpp"

namespace sqlproxy {

namespace keys {
    inline constexpr std::string_view RATE_LIMIT_BREACH     = "rate_limit_breach";
    inline constexpr std::string_view POLICY_VIOLATION_SPIKE = "policy_violation_spike";
    inline constexpr std::string_view CIRCUIT_BREAKER_OPEN   = "circuit_breaker_open";
    inline constexpr std::string_view PII_EXPOSURE_SPIKE     = "pii_exposure_spike";
    inline constexpr std::string_view AUDIT_BUFFER_OVERFLOW  = "audit_buffer_overflow";
    inline constexpr std::string_view CUSTOM_METRIC          = "custom_metric";
}

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

[[nodiscard]] constexpr std::string_view alert_condition_to_string(AlertCondition c) {
    switch (c) {
        case AlertCondition::RATE_LIMIT_BREACH:     return keys::RATE_LIMIT_BREACH;
        case AlertCondition::POLICY_VIOLATION_SPIKE: return keys::POLICY_VIOLATION_SPIKE;
        case AlertCondition::CIRCUIT_BREAKER_OPEN:   return keys::CIRCUIT_BREAKER_OPEN;
        case AlertCondition::PII_EXPOSURE_SPIKE:     return keys::PII_EXPOSURE_SPIKE;
        case AlertCondition::AUDIT_BUFFER_OVERFLOW:  return keys::AUDIT_BUFFER_OVERFLOW;
        case AlertCondition::CUSTOM_METRIC:          return keys::CUSTOM_METRIC;
        default: return "unknown";
    }
}

[[nodiscard]] inline AlertCondition parse_alert_condition(std::string_view s) {
    // The keys are constexpr string_views, but the map is static runtime
    static const std::unordered_map<std::string_view, AlertCondition> lookup = {
        {keys::RATE_LIMIT_BREACH,     AlertCondition::RATE_LIMIT_BREACH},
        {keys::POLICY_VIOLATION_SPIKE, AlertCondition::POLICY_VIOLATION_SPIKE},
        {keys::CIRCUIT_BREAKER_OPEN,   AlertCondition::CIRCUIT_BREAKER_OPEN},
        {keys::PII_EXPOSURE_SPIKE,     AlertCondition::PII_EXPOSURE_SPIKE},
        {keys::AUDIT_BUFFER_OVERFLOW,  AlertCondition::AUDIT_BUFFER_OVERFLOW},
    };

    const auto it = lookup.find(s);
    return (it != lookup.end()) ? it->second : AlertCondition::CUSTOM_METRIC;
}

} // namespace sqlproxy
