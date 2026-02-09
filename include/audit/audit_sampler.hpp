#pragma once

#include "core/types.hpp"
#include <atomic>
#include <cstdint>

namespace sqlproxy {

class AuditSampler {
public:
    struct Config {
        bool enabled = false;
        double default_sample_rate = 1.0;   // 1.0 = log all
        double select_sample_rate = 1.0;
        bool always_log_blocked = true;
        bool always_log_writes = true;
        bool always_log_errors = true;
        bool deterministic = true;           // Hash-based consistent sampling
    };

    explicit AuditSampler(const Config& config);

    /// Returns true if this record should be emitted
    [[nodiscard]] bool should_sample(
        StatementType stmt_type,
        Decision decision,
        ErrorCode error_code,
        uint64_t fingerprint_hash) const;

    [[nodiscard]] bool is_enabled() const { return config_.enabled; }

    struct Stats {
        uint64_t total_checked;
        uint64_t total_sampled;
        uint64_t total_dropped;
    };
    [[nodiscard]] Stats get_stats() const;

private:
    [[nodiscard]] bool rate_check(double rate, uint64_t fingerprint_hash) const;

    Config config_;
    mutable std::atomic<uint64_t> total_checked_{0};
    mutable std::atomic<uint64_t> total_sampled_{0};
};

} // namespace sqlproxy
