#include "alerting/alert_evaluator.hpp"
#include "server/http_constants.hpp"
#include "server/rate_limiter.hpp"
#include "core/utils.hpp"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include "../third_party/cpp-httplib/httplib.h"
#pragma GCC diagnostic pop

#include <format>
#include <fstream>

namespace sqlproxy {

AlertEvaluator::AlertEvaluator(
    const AlertingConfig& config,
    std::shared_ptr<AuditEmitter> audit_emitter,
    std::shared_ptr<IRateLimiter> rate_limiter)
    : config_(config),
      evaluation_interval_(config.evaluation_interval_seconds),
      audit_emitter_(std::move(audit_emitter)),
      rate_limiter_(std::move(rate_limiter)),
      rules_(config.rules) {}

AlertEvaluator::~AlertEvaluator() {
    stop();
}

void AlertEvaluator::start() {
    if (!config_.enabled) return;

    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) return;

    prev_snapshot_ = collect_metrics();
    eval_thread_ = std::thread(&AlertEvaluator::evaluator_loop, this);
}

void AlertEvaluator::stop() {
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false)) return;

    cv_.notify_one();
    if (eval_thread_.joinable()) {
        eval_thread_.join();
    }
}

std::vector<Alert> AlertEvaluator::active_alerts() const {
    std::lock_guard lock(alerts_mutex_);
    std::vector<Alert> result;
    result.reserve(active_alerts_.size());
    for (const auto& [name, alert] : active_alerts_) {
        result.push_back(alert);
    }
    return result;
}

std::vector<Alert> AlertEvaluator::alert_history() const {
    std::lock_guard lock(alerts_mutex_);
    return alert_history_;
}

void AlertEvaluator::reload_rules(const std::vector<AlertRule>& new_rules) {
    std::unique_lock lock(rules_mutex_);
    rules_ = new_rules;
}

AlertEvaluator::Stats AlertEvaluator::get_stats() const {
    Stats s;
    s.evaluations = evaluation_count_.load(std::memory_order_relaxed);
    s.alerts_fired = alerts_fired_count_.load(std::memory_order_relaxed);
    s.alerts_resolved = alerts_resolved_count_.load(std::memory_order_relaxed);
    {
        std::lock_guard lock(alerts_mutex_);
        s.active_alert_count = active_alerts_.size();
    }
    {
        std::shared_lock lock(rules_mutex_);
        s.rule_count = rules_.size();
    }
    return s;
}

void AlertEvaluator::evaluator_loop() {
    while (running_.load(std::memory_order_acquire)) {
        {
            std::unique_lock lock(cv_mutex_);
            cv_.wait_for(lock, evaluation_interval_, [this] {
                return !running_.load(std::memory_order_acquire);
            });
        }

        if (!running_.load(std::memory_order_acquire)) break;

        const auto current = collect_metrics();
        evaluate_rules(current, prev_snapshot_);
        prev_snapshot_ = current;
        evaluation_count_.fetch_add(1, std::memory_order_relaxed);
    }
}

AlertEvaluator::MetricSnapshot AlertEvaluator::collect_metrics() {
    MetricSnapshot snap;

    if (audit_emitter_) {
        const auto stats = audit_emitter_->get_stats();
        snap.audit_overflow = stats.overflow_dropped;
        snap.audit_emitted = stats.total_emitted;
        snap.audit_written = stats.total_written;
    }

    // Rate limiter rejects
    const auto* hierarchical = dynamic_cast<HierarchicalRateLimiter*>(rate_limiter_.get());
    if (hierarchical) {
        const auto rl_stats = hierarchical->get_stats();
        snap.rate_limit_rejects = rl_stats.global_rejects
                                + rl_stats.user_rejects
                                + rl_stats.database_rejects
                                + rl_stats.user_database_rejects;
    }

    return snap;
}

void AlertEvaluator::evaluate_rules(const MetricSnapshot& current, const MetricSnapshot& previous) {
    std::shared_lock rules_lock(rules_mutex_);

    const auto now = std::chrono::steady_clock::now();

    for (const auto& rule : rules_) {
        if (!rule.enabled) continue;

        // Check cooldown
        {
            std::lock_guard alert_lock(alerts_mutex_);
            const auto cool_it = cooldowns_.find(rule.name);
            if (cool_it != cooldowns_.end()) {
                if (now - cool_it->second < rule.cooldown) continue;
            }
        }

        double delta = 0.0;

        switch (rule.condition) {
            case AlertCondition::RATE_LIMIT_BREACH:
                delta = static_cast<double>(current.rate_limit_rejects - previous.rate_limit_rejects);
                break;
            case AlertCondition::POLICY_VIOLATION_SPIKE:
                delta = static_cast<double>(current.policy_violations - previous.policy_violations);
                break;
            case AlertCondition::CIRCUIT_BREAKER_OPEN:
                // Circuit breaker is checked as absolute state, not delta
                delta = 0.0; // Would need circuit breaker reference for real check
                break;
            case AlertCondition::PII_EXPOSURE_SPIKE:
                // PII exposure tracking would come from classifier stats
                delta = 0.0;
                break;
            case AlertCondition::AUDIT_BUFFER_OVERFLOW:
                delta = static_cast<double>(current.audit_overflow - previous.audit_overflow);
                break;
            case AlertCondition::CUSTOM_METRIC:
                break;
        }

        if (delta >= rule.threshold) {
            fire_alert(rule, delta);
        } else {
            // Check if previously active alert should be resolved
            std::lock_guard alert_lock(alerts_mutex_);
            if (active_alerts_.contains(rule.name)) {
                resolve_alert(rule.name);
            }
        }
    }
}

void AlertEvaluator::fire_alert(const AlertRule& rule, double current_value) {
    Alert alert;
    alert.rule_name = rule.name;
    alert.condition = rule.condition;
    alert.severity = rule.severity;
    alert.current_value = current_value;
    alert.threshold = rule.threshold;
    alert.message = std::format("{}: {} ({:.0f} >= {:.0f})",
        rule.severity, rule.name, current_value, rule.threshold);

    {
        std::lock_guard lock(alerts_mutex_);
        // Don't re-fire if already active
        if (active_alerts_.contains(rule.name)) return;

        active_alerts_[rule.name] = alert;
        alert_history_.push_back(alert);
        cooldowns_[rule.name] = std::chrono::steady_clock::now();
    }

    alerts_fired_count_.fetch_add(1, std::memory_order_relaxed);
    write_alert_log(alert);

    if (config_.webhook.enabled && !config_.webhook.url.empty()) {
        send_webhook(alert);
    }
}

void AlertEvaluator::resolve_alert(const std::string& rule_name) {
    // Caller must hold alerts_mutex_
    const auto it = active_alerts_.find(rule_name);
    if (it == active_alerts_.end()) return;

    Alert resolved = it->second;
    resolved.resolved = true;
    alert_history_.emplace_back(std::move(resolved));
    active_alerts_.erase(it);

    alerts_resolved_count_.fetch_add(1, std::memory_order_relaxed);
}

void AlertEvaluator::write_alert_log(const Alert& alert) {
    if (config_.alert_log_file.empty()) return;

    std::string json = alert_to_json(alert);
    json += '\n';

    std::ofstream ofs(config_.alert_log_file, std::ios::app);
    if (ofs.is_open()) {
        ofs.write(json.data(), static_cast<std::streamsize>(json.size()));
    }
}

void AlertEvaluator::send_webhook(const Alert& alert) {
    try {
        const std::string json = alert_to_json(alert);

        // Parse URL
        std::string url = config_.webhook.url;
        std::string host;
        std::string path = "/";
        int port = 443;
        bool use_ssl = true;

        if (url.starts_with("https://")) {
            url = url.substr(8);
        } else if (url.starts_with("http://")) {
            url = url.substr(7);
            use_ssl = false;
            port = 80;
        }

        const auto path_pos = url.find('/');
        if (path_pos != std::string::npos) {
            path = url.substr(path_pos);
            url = url.substr(0, path_pos);
        }

        const auto port_pos = url.find(':');
        if (port_pos != std::string::npos) {
            port = utils::parse_int<int>(std::string_view(url).substr(port_pos + 1), port);
            host = url.substr(0, port_pos);
        } else {
            host = url;
        }

        const std::string scheme_host = std::format("{}{}:{}", use_ssl ? "https://" : "http://", host, port);
        httplib::Client cli(scheme_host);
        cli.set_connection_timeout(5);
        httplib::Headers headers;
        if (!config_.webhook.auth_header.empty()) {
            headers.emplace(http::kAuthorizationHeader, config_.webhook.auth_header);
        }
        cli.Post(path, headers, json, http::kJsonContentType);
    } catch (const std::exception& e) {
        utils::log::error(std::format("Alert webhook failed ({}): {}", config_.webhook.url, e.what()));
    } catch (...) {
        utils::log::error(std::format("Alert webhook failed ({}): unknown error", config_.webhook.url));
    }
}

std::string AlertEvaluator::alert_to_json(const Alert& alert) const {
    return std::format(
        "{{\"id\":\"{}\",\"rule_name\":\"{}\",\"condition\":\"{}\","
        "\"severity\":\"{}\",\"current_value\":{:.2f},\"threshold\":{:.2f},"
        "\"message\":\"{}\",\"fired_at\":\"{}\",\"resolved\":{}}}",
        alert.id, alert.rule_name,
        alert_condition_to_string(alert.condition),
        alert.severity, alert.current_value, alert.threshold,
        alert.message,
        utils::format_timestamp(alert.fired_at),
        utils::booltostr(alert.resolved));
}

} // namespace sqlproxy
