#include "security/brute_force_protector.hpp"

#include <algorithm>
#include <format>
#include <mutex>

namespace sqlproxy {

BruteForceProtector::BruteForceProtector(const Config& config)
    : config_(config) {}

BruteForceProtector::BlockStatus BruteForceProtector::is_blocked(
    const std::string& ip, const std::string& username) const {

    if (!config_.enabled) return {};

    // Check IP
    {
        std::shared_lock lock(ip_mutex_);
        if (const auto it = ip_records_.find(ip); it != ip_records_.end()) {
            auto status = check_record(it->second);
            if (status.blocked) {
                status.reason = std::format("IP {} is locked out", ip);
                total_blocks_.fetch_add(1, std::memory_order_relaxed);
                return status;
            }
        }
    }

    // Check username
    {
        std::shared_lock lock(user_mutex_);
        if (const auto it = user_records_.find(username); it != user_records_.end()) {
            auto status = check_record(it->second);
            if (status.blocked) {
                status.reason = std::format("User '{}' is locked out", username);
                total_blocks_.fetch_add(1, std::memory_order_relaxed);
                return status;
            }
        }
    }

    return {};
}

void BruteForceProtector::record_failure(const std::string& ip, const std::string& username) {
    if (!config_.enabled) return;

    total_failures_.fetch_add(1, std::memory_order_relaxed);

    // Periodic eviction: every 1000 failures, clean expired entries
    if (eviction_counter_.fetch_add(1, std::memory_order_relaxed) % 1000 == 0) {
        evict_expired();
    }

    const auto now = std::chrono::steady_clock::now();

    // Update IP record
    {
        std::unique_lock lock(ip_mutex_);
        auto& record = ip_records_[ip];
        prune_and_update(record);
        record.timestamps.push_back(now);
        if (record.timestamps.size() >= config_.max_attempts) {
            const uint32_t lockout = std::min(
                config_.lockout_seconds * (1u << record.consecutive_lockouts),
                config_.max_lockout_seconds);
            record.locked_until = now + std::chrono::seconds(lockout);
            ++record.consecutive_lockouts;
            record.timestamps.clear();
        }
    }

    // Update username record
    {
        std::unique_lock lock(user_mutex_);
        auto& record = user_records_[username];
        prune_and_update(record);
        record.timestamps.push_back(now);
        if (record.timestamps.size() >= config_.max_attempts) {
            const uint32_t lockout = std::min(
                config_.lockout_seconds * (1u << record.consecutive_lockouts),
                config_.max_lockout_seconds);
            record.locked_until = now + std::chrono::seconds(lockout);
            ++record.consecutive_lockouts;
            record.timestamps.clear();
        }
    }
}

void BruteForceProtector::record_success(const std::string& ip, const std::string& username) {
    if (!config_.enabled) return;

    {
        std::unique_lock lock(ip_mutex_);
        ip_records_.erase(ip);
    }
    {
        std::unique_lock lock(user_mutex_);
        user_records_.erase(username);
    }
}

BruteForceProtector::BlockStatus BruteForceProtector::check_record(
    const FailureRecord& record) const {

    const auto now = std::chrono::steady_clock::now();
    if (record.locked_until > now) {
        const auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
            record.locked_until - now).count();
        return {.blocked = true, .retry_after_seconds = static_cast<uint32_t>(remaining)};
    }
    return {};
}

void BruteForceProtector::prune_and_update(FailureRecord& record) {
    const auto now = std::chrono::steady_clock::now();
    const auto window = std::chrono::seconds(config_.window_seconds);

    // Remove timestamps outside the window
    auto it = std::remove_if(record.timestamps.begin(), record.timestamps.end(),
        [&](const auto& ts) { return (now - ts) > window; });
    record.timestamps.erase(it, record.timestamps.end());
}

template<typename Map>
void BruteForceProtector::evict_expired_from(Map& records) {
    const auto now = std::chrono::steady_clock::now();
    const auto expiry = std::chrono::seconds(config_.window_seconds + config_.max_lockout_seconds);

    for (auto it = records.begin(); it != records.end(); ) {
        const auto& rec = it->second;
        // Evict if: lockout expired AND no recent timestamps
        const bool lockout_expired = rec.locked_until <= now;
        bool timestamps_expired = true;
        for (const auto& ts : rec.timestamps) {
            if ((now - ts) <= expiry) {
                timestamps_expired = false;
                break;
            }
        }
        if (lockout_expired && (rec.timestamps.empty() || timestamps_expired)) {
            it = records.erase(it);
        } else {
            ++it;
        }
    }
}

void BruteForceProtector::evict_expired() {
    {
        std::unique_lock lock(ip_mutex_);
        evict_expired_from(ip_records_);
        // Hard cap: if still over limit, drop oldest entries
        while (ip_records_.size() > config_.max_tracked_entries) {
            ip_records_.erase(ip_records_.begin());
        }
    }
    {
        std::unique_lock lock(user_mutex_);
        evict_expired_from(user_records_);
        while (user_records_.size() > config_.max_tracked_entries) {
            user_records_.erase(user_records_.begin());
        }
    }
}

} // namespace sqlproxy
