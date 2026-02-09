#include "security/anomaly_detector.hpp"

#include <cmath>
#include <format>
#include <mutex>
#include <numeric>

namespace sqlproxy {

AnomalyDetector::AnomalyDetector(const Config& config)
    : config_(config) {}

AnomalyDetector::AnomalyResult AnomalyDetector::check(
    const std::string& user,
    const std::vector<std::string>& tables,
    uint64_t fingerprint_hash) const {

    if (!config_.enabled) return {};

    std::shared_lock lock(mutex_);

    const auto it = profiles_.find(user);
    if (it == profiles_.end()) return {};
    const auto& profile = it->second;

    AnomalyResult result;
    double score = 0.0;

    // 1. New table access (only after baseline established)
    if (profile->total_queries.load() >= config_.new_table_alert_after_queries) {
        for (const auto& table : tables) {
            if (!profile->known_tables.contains(table)) {
                result.anomalies.push_back("NEW_TABLE:" + table);
                score += 0.3;
            }
        }
    }

    // 2. New query pattern
    if (profile->total_queries.load() >= config_.new_table_alert_after_queries &&
        fingerprint_hash != 0 && !profile->known_fingerprints.contains(fingerprint_hash)) {
        result.anomalies.push_back("NEW_QUERY_PATTERN");
        score += 0.2;
    }

    // 3. Volume spike
    if (profile->avg_queries_per_window > 0 && profile->stddev_queries_per_window > 0) {
        const double current = static_cast<double>(profile->window_queries.load());
        const double z_score = (current - profile->avg_queries_per_window) /
                         profile->stddev_queries_per_window;
        if (z_score > config_.volume_stddev_threshold) {
            result.anomalies.push_back(std::format("VOLUME_SPIKE:{:.1f}σ", z_score));
            score += 0.4;
        }
    }

    // 4. Unusual hour
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    struct tm tm_now;
    gmtime_r(&time_t_now, &tm_now);
    int current_hour = tm_now.tm_hour;

    if (profile->total_queries.load() >= config_.new_table_alert_after_queries) {
        const auto it = profile->hour_distribution.find(current_hour);
        if (it == profile->hour_distribution.end() || it->second == 0) {
            result.anomalies.push_back(std::format("UNUSUAL_HOUR:{}", current_hour));
            score += 0.2;
        }
    }

    result.anomaly_score = std::min(score, 1.0);
    result.is_anomalous = result.anomaly_score >= 0.5;

    return result;
}

void AnomalyDetector::record(
    const std::string& user,
    const std::vector<std::string>& tables,
    uint64_t fingerprint_hash) {

    if (!config_.enabled) return;

    auto profile = get_or_create_profile(user);

    std::unique_lock lock(mutex_);

    profile->total_queries.fetch_add(1);
    profile->window_queries.fetch_add(1);
    profile->last_seen = std::chrono::system_clock::now();

    // Track tables
    for (const auto& table : tables) {
        profile->known_tables.insert(table);
    }

    // Track fingerprint
    if (fingerprint_hash != 0) {
        profile->known_fingerprints.insert(fingerprint_hash);
    }

    // Track hour distribution
    auto time_t_now = std::chrono::system_clock::to_time_t(profile->last_seen);
    struct tm tm_now;
    gmtime_r(&time_t_now, &tm_now);
    ++profile->hour_distribution[tm_now.tm_hour];

    // Rotate window if needed
    maybe_rotate_window(*profile);
}

size_t AnomalyDetector::tracked_users() const {
    std::shared_lock lock(mutex_);
    return profiles_.size();
}

std::shared_ptr<UserProfile> AnomalyDetector::get_or_create_profile(const std::string& user) {
    // Fast path: shared lock
    {
        std::shared_lock lock(mutex_);
        const auto it = profiles_.find(user);
        if (it != profiles_.end()) return it->second;
    }

    // Slow path: unique lock + double-check
    std::unique_lock lock(mutex_);
    auto [it, inserted] = profiles_.try_emplace(user, nullptr);
    if (inserted) {
        auto profile = std::make_shared<UserProfile>();
        profile->profile_created = std::chrono::system_clock::now();
        profile->window_start = profile->profile_created;
        it->second = std::move(profile);
    }
    return it->second;
}

std::shared_ptr<UserProfile> AnomalyDetector::find_profile(const std::string& user) const {
    std::shared_lock lock(mutex_);
    const auto it = profiles_.find(user);
    return (it != profiles_.end()) ? it->second : nullptr;
}

void AnomalyDetector::maybe_rotate_window(UserProfile& profile) const {
    const auto now = std::chrono::system_clock::now();
    const auto window_duration = std::chrono::minutes(config_.baseline_window_minutes);

    if (now - profile.window_start >= window_duration) {
        // Save current window count
        uint64_t window_count = profile.window_queries.exchange(0);
        profile.window_history.push_back(window_count);

        // Trim history
        while (profile.window_history.size() > config_.max_window_history) {
            profile.window_history.erase(profile.window_history.begin());
        }

        // Recalculate stats
        if (profile.window_history.size() >= 2) {
            const double sum = std::accumulate(profile.window_history.begin(),
                                         profile.window_history.end(), 0.0);
            const double n = static_cast<double>(profile.window_history.size());
            profile.avg_queries_per_window = sum / n;

            double sq_sum = 0.0;
            for (auto v : profile.window_history) {
                const double diff = static_cast<double>(v) - profile.avg_queries_per_window;
                sq_sum += diff * diff;
            }
            profile.stddev_queries_per_window = std::sqrt(sq_sum / n);
        }

        profile.window_start = now;
    }
}

} // namespace sqlproxy
