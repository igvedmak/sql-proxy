#include "security/sql_firewall.hpp"

#include <mutex>

namespace sqlproxy {

SqlFirewall::SqlFirewall() : SqlFirewall(Config{}) {}

SqlFirewall::SqlFirewall(Config config)
    : config_(std::move(config)),
      mode_(config_.initial_mode) {}

SqlFirewall::CheckResult SqlFirewall::check(uint64_t fingerprint_hash) const {
    const auto current_mode = mode_.load(std::memory_order_acquire);

    if (current_mode == FirewallMode::DISABLED) {
        return {true, false};
    }

    std::shared_lock lock(mutex_);
    const bool known = allowlist_.contains(fingerprint_hash);

    if (current_mode == FirewallMode::LEARNING) {
        return {true, !known};
    }

    // ENFORCING: only allow known fingerprints
    return {known, !known};
}

void SqlFirewall::record(uint64_t fingerprint_hash) {
    const auto current_mode = mode_.load(std::memory_order_acquire);
    if (current_mode != FirewallMode::LEARNING) return;

    // Double-checked locking: fast path with shared lock
    {
        std::shared_lock lock(mutex_);
        if (allowlist_.contains(fingerprint_hash)) return;
    }

    std::unique_lock lock(mutex_);
    allowlist_.insert(fingerprint_hash);
}

void SqlFirewall::set_mode(FirewallMode mode) {
    mode_.store(mode, std::memory_order_release);
}

FirewallMode SqlFirewall::mode() const {
    return mode_.load(std::memory_order_acquire);
}

size_t SqlFirewall::allowlist_size() const {
    std::shared_lock lock(mutex_);
    return allowlist_.size();
}

std::vector<uint64_t> SqlFirewall::get_allowlist() const {
    std::shared_lock lock(mutex_);
    return {allowlist_.begin(), allowlist_.end()};
}

} // namespace sqlproxy
