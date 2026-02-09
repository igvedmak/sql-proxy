#include "audit/audit_sampler.hpp"

#include <random>

namespace sqlproxy {

AuditSampler::AuditSampler(const Config& config)
    : config_(config) {}

bool AuditSampler::should_sample(
    StatementType stmt_type,
    Decision decision,
    ErrorCode error_code,
    uint64_t fingerprint_hash) const {

    total_checked_.fetch_add(1, std::memory_order_relaxed);

    if (!config_.enabled) {
        total_sampled_.fetch_add(1, std::memory_order_relaxed);
        return true;  // Sampling disabled = log everything
    }

    // Always-log rules (short-circuit)
    if (config_.always_log_blocked && decision == Decision::BLOCK) {
        total_sampled_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    if (config_.always_log_errors && error_code != ErrorCode::NONE) {
        total_sampled_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    if (config_.always_log_writes &&
        stmt_mask::test(stmt_type, stmt_mask::kWrite)) {
        total_sampled_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    // Probabilistic/deterministic sampling
    double rate = (stmt_type == StatementType::SELECT)
        ? config_.select_sample_rate
        : config_.default_sample_rate;

    if (rate_check(rate, fingerprint_hash)) {
        total_sampled_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    return false;
}

bool AuditSampler::rate_check(double rate, uint64_t fingerprint_hash) const {
    if (rate >= 1.0) return true;
    if (rate <= 0.0) return false;

    if (config_.deterministic) {
        // Deterministic: hash mod 10000, compare against rate*10000
        // Same fingerprint always produces same decision
        uint32_t bucket = static_cast<uint32_t>(fingerprint_hash % 10000);
        return bucket < static_cast<uint32_t>(rate * 10000);
    } else {
        // Probabilistic: thread-local RNG
        static thread_local std::mt19937 rng(std::random_device{}());
        std::uniform_real_distribution<double> dist(0.0, 1.0);
        return dist(rng) < rate;
    }
}

AuditSampler::Stats AuditSampler::get_stats() const {
    uint64_t checked = total_checked_.load(std::memory_order_relaxed);
    uint64_t sampled = total_sampled_.load(std::memory_order_relaxed);
    return {checked, sampled, checked - sampled};
}

} // namespace sqlproxy
