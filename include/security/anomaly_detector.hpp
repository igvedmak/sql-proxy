#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace sqlproxy {

struct UserProfile {
    std::atomic<uint64_t> total_queries{0};
    std::atomic<uint64_t> window_queries{0};

    // Baseline patterns (protected by parent's shared_mutex)
    std::unordered_set<std::string> known_tables;
    std::unordered_set<uint64_t> known_fingerprints;
    std::unordered_map<int, uint64_t> hour_distribution;

    // Rolling stats
    double avg_queries_per_window = 0.0;
    double stddev_queries_per_window = 0.0;
    std::vector<uint64_t> window_history;

    std::chrono::system_clock::time_point last_seen;
    std::chrono::system_clock::time_point profile_created;
    std::chrono::system_clock::time_point window_start;
};

class AnomalyDetector {
public:
    struct Config {
        bool enabled = true;
        size_t baseline_window_minutes = 5;
        double volume_stddev_threshold = 3.0;
        size_t new_table_alert_after_queries = 100;
        size_t max_window_history = 288; // 24h of 5-min windows
    };

    struct AnomalyResult {
        double anomaly_score = 0.0;
        std::vector<std::string> anomalies;
        bool is_anomalous = false;
    };

    AnomalyDetector() : AnomalyDetector(Config{}) {}
    explicit AnomalyDetector(const Config& config);

    [[nodiscard]] AnomalyResult check(
        const std::string& user,
        const std::vector<std::string>& tables,
        uint64_t fingerprint_hash) const;

    void record(
        const std::string& user,
        const std::vector<std::string>& tables,
        uint64_t fingerprint_hash);

    [[nodiscard]] size_t tracked_users() const;

private:
    std::shared_ptr<UserProfile> get_or_create_profile(const std::string& user);
    [[nodiscard]] std::shared_ptr<UserProfile> find_profile(const std::string& user) const;
    void maybe_rotate_window(UserProfile& profile) const;

    Config config_;
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<UserProfile>> profiles_;
};

} // namespace sqlproxy
