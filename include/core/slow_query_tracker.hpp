#pragma once

#include "core/types.hpp"
#include <atomic>
#include <chrono>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace sqlproxy {

struct SlowQueryRecord {
    std::string user;
    std::string database;
    std::string sql;
    std::string fingerprint;
    std::chrono::microseconds execution_time;
    std::chrono::system_clock::time_point timestamp;
    StatementType statement_type;

    SlowQueryRecord()
        : execution_time(0),
          timestamp(std::chrono::system_clock::now()),
          statement_type(StatementType::UNKNOWN) {}
};

class SlowQueryTracker {
public:
    struct Config {
        bool enabled = false;
        uint32_t threshold_ms = 500;
        size_t max_entries = 1000;
    };

    SlowQueryTracker() : SlowQueryTracker(Config{}) {}
    explicit SlowQueryTracker(const Config& config);

    /**
     * @brief Record a query if it exceeds the slow query threshold
     * @return true if the query was recorded (was slow)
     */
    bool record_if_slow(const SlowQueryRecord& record);

    /**
     * @brief Get recent slow queries
     * @param limit Max entries to return (0 = all)
     */
    [[nodiscard]] std::vector<SlowQueryRecord> get_recent(size_t limit = 0) const;

    [[nodiscard]] uint64_t total_slow_queries() const {
        return total_slow_queries_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] bool is_enabled() const { return config_.enabled; }

    [[nodiscard]] uint32_t threshold_ms() const { return config_.threshold_ms; }

private:
    Config config_;
    mutable std::mutex mutex_;
    std::deque<SlowQueryRecord> records_;
    std::atomic<uint64_t> total_slow_queries_{0};
};

} // namespace sqlproxy
