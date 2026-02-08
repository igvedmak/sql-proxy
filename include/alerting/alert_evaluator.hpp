#pragma once

#include "alerting/alert_types.hpp"
#include "audit/audit_emitter.hpp"
#include "server/irate_limiter.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace sqlproxy {

// Forward declarations
class HierarchicalRateLimiter;

/**
 * @brief Background alert evaluator
 *
 * Periodically collects metric snapshots from existing components
 * (AuditEmitter, RateLimiter) and evaluates alert rules. Fires
 * alerts when thresholds are breached, with cooldown tracking to
 * prevent alert storms.
 *
 * Alert sinks: JSONL file + optional webhook.
 */
class AlertEvaluator {
public:
    AlertEvaluator(
        const AlertingConfig& config,
        std::shared_ptr<AuditEmitter> audit_emitter,
        std::shared_ptr<IRateLimiter> rate_limiter);

    ~AlertEvaluator();

    AlertEvaluator(const AlertEvaluator&) = delete;
    AlertEvaluator& operator=(const AlertEvaluator&) = delete;

    void start();
    void stop();

    /// Get currently active (unresolved) alerts
    [[nodiscard]] std::vector<Alert> active_alerts() const;

    /// Get recent alert history (fired + resolved)
    [[nodiscard]] std::vector<Alert> alert_history() const;

    /// Hot-reload alert rules (thread-safe)
    void reload_rules(const std::vector<AlertRule>& new_rules);

    struct Stats {
        uint64_t evaluations = 0;
        uint64_t alerts_fired = 0;
        uint64_t alerts_resolved = 0;
        size_t active_alert_count = 0;
        size_t rule_count = 0;
    };

    [[nodiscard]] Stats get_stats() const;

private:
    struct MetricSnapshot {
        uint64_t rate_limit_rejects = 0;
        uint64_t policy_violations = 0;
        uint64_t audit_overflow = 0;
        uint64_t audit_emitted = 0;
        uint64_t audit_written = 0;
    };

    void evaluator_loop();
    MetricSnapshot collect_metrics();
    void evaluate_rules(const MetricSnapshot& current, const MetricSnapshot& previous);
    void fire_alert(const AlertRule& rule, double current_value);
    void resolve_alert(const std::string& rule_name);
    void write_alert_log(const Alert& alert);
    void send_webhook(const Alert& alert);
    std::string alert_to_json(const Alert& alert) const;

    // Config
    AlertingConfig config_;
    std::chrono::seconds evaluation_interval_;

    // Components
    std::shared_ptr<AuditEmitter> audit_emitter_;
    std::shared_ptr<IRateLimiter> rate_limiter_;

    // Rules (hot-reloadable)
    std::vector<AlertRule> rules_;
    mutable std::shared_mutex rules_mutex_;

    // Alert state
    std::unordered_map<std::string, Alert> active_alerts_;
    std::vector<Alert> alert_history_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> cooldowns_;
    mutable std::mutex alerts_mutex_;

    // Previous metric snapshot (for delta computation)
    MetricSnapshot prev_snapshot_;

    // Background thread
    std::thread eval_thread_;
    std::atomic<bool> running_{false};
    std::mutex cv_mutex_;
    std::condition_variable cv_;

    // Stats
    std::atomic<uint64_t> evaluation_count_{0};
    std::atomic<uint64_t> alerts_fired_count_{0};
    std::atomic<uint64_t> alerts_resolved_count_{0};
};

} // namespace sqlproxy
