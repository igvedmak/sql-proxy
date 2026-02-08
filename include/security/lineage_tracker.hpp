#pragma once

#include <chrono>
#include <deque>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace sqlproxy {

struct LineageEvent {
    std::string timestamp;
    std::string user;
    std::string database;
    std::string table;
    std::string column;
    std::string classification;
    std::string access_type;
    std::string query_fingerprint;
    bool was_masked = false;
    std::string masking_action;
};

struct LineageSummary {
    std::string column_key;         // "testdb.customers.email"
    std::string classification;
    uint64_t total_accesses = 0;
    uint64_t masked_accesses = 0;
    uint64_t unmasked_accesses = 0;
    std::unordered_set<std::string> accessing_users;
    std::chrono::system_clock::time_point first_access;
    std::chrono::system_clock::time_point last_access;
};

class LineageTracker {
public:
    struct Config {
        bool enabled = true;
        size_t max_events = 100000;
    };

    LineageTracker() : LineageTracker(Config{}) {}
    explicit LineageTracker(const Config& config);

    void record(const LineageEvent& event);

    [[nodiscard]] std::vector<LineageSummary> get_summaries() const;
    [[nodiscard]] std::vector<LineageEvent> get_events(
        const std::string& user = "",
        const std::string& table = "",
        size_t limit = 100) const;
    [[nodiscard]] size_t total_events() const;

private:
    Config config_;
    mutable std::shared_mutex mutex_;
    std::deque<LineageEvent> events_;
    std::unordered_map<std::string, LineageSummary> summaries_;
};

} // namespace sqlproxy
