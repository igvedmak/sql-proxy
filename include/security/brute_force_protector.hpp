#pragma once

#include <atomic>
#include <chrono>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace sqlproxy {

class BruteForceProtector {
public:
    struct Config {
        bool enabled = true;
        uint32_t max_attempts = 5;
        uint32_t window_seconds = 60;
        uint32_t lockout_seconds = 300;
        uint32_t max_lockout_seconds = 3600;
        size_t max_tracked_entries = 100000;  // Cap to prevent memory exhaustion
    };

    struct BlockStatus {
        bool blocked = false;
        uint32_t retry_after_seconds = 0;
        std::string reason;
    };

    BruteForceProtector() : BruteForceProtector(Config{}) {}
    explicit BruteForceProtector(const Config& config);

    [[nodiscard]] BlockStatus is_blocked(const std::string& ip,
                                          const std::string& username) const;
    void record_failure(const std::string& ip, const std::string& username);
    void record_success(const std::string& ip, const std::string& username);

    /// Evict expired records to bound memory growth. Called periodically from record_failure.
    void evict_expired();

    [[nodiscard]] uint64_t total_failures() const {
        return total_failures_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] uint64_t total_blocks() const {
        return total_blocks_.load(std::memory_order_relaxed);
    }

private:
    struct FailureRecord {
        std::vector<std::chrono::steady_clock::time_point> timestamps;
        uint32_t consecutive_lockouts = 0;
        std::chrono::steady_clock::time_point locked_until{};
    };

    [[nodiscard]] BlockStatus check_record(const FailureRecord& record) const;
    void prune_and_update(FailureRecord& record);

    Config config_;

    mutable std::shared_mutex ip_mutex_;
    mutable std::shared_mutex user_mutex_;
    mutable std::unordered_map<std::string, FailureRecord> ip_records_;
    mutable std::unordered_map<std::string, FailureRecord> user_records_;

    mutable std::atomic<uint64_t> total_failures_{0};
    mutable std::atomic<uint64_t> total_blocks_{0};
    std::atomic<uint64_t> eviction_counter_{0};  // Tracks record_failure calls for periodic eviction

    /// Evict expired entries from a single map (helper, must hold unique_lock)
    template<typename Map>
    void evict_expired_from(Map& records);
};

} // namespace sqlproxy
