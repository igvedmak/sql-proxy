#pragma once

#include "core/types.hpp"
#include "db/iconnection_pool.hpp"
#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace sqlproxy {

/**
 * @brief Schema Drift Detector — periodically snapshots database schema
 *        and detects unauthorized changes (columns added/dropped/altered).
 *
 * Runs a background thread that queries information_schema every N seconds,
 * compares against a stored baseline, and records drift events.
 */
class SchemaDriftDetector {
public:
    struct Config {
        bool enabled = false;
        int check_interval_seconds = 600;    // 10 minutes default
        std::string database = "testdb";
        std::string schema_name = "public";
    };

    struct ColumnSnapshot {
        std::string table_name;
        std::string column_name;
        std::string data_type;
        bool is_nullable = true;
    };

    struct DriftEvent {
        std::string timestamp;
        std::string change_type;             // "COLUMN_ADDED", "COLUMN_DROPPED", "COLUMN_ALTERED"
        std::string table_name;
        std::string column_name;
        std::string old_type;                // For ALTERED
        std::string new_type;                // For ALTERED / ADDED
    };

    explicit SchemaDriftDetector(std::shared_ptr<IConnectionPool> pool, Config config);
    ~SchemaDriftDetector();

    void start();
    void stop();

    [[nodiscard]] bool is_enabled() const { return config_.enabled; }
    [[nodiscard]] std::vector<DriftEvent> get_drift_events() const;
    [[nodiscard]] uint64_t total_drifts() const { return total_drifts_.load(std::memory_order_relaxed); }
    [[nodiscard]] uint64_t checks_performed() const { return checks_performed_.load(std::memory_order_relaxed); }

private:
    void run_loop();
    std::vector<ColumnSnapshot> fetch_current_schema() const;
    void detect_drift(const std::vector<ColumnSnapshot>& current);

    std::shared_ptr<IConnectionPool> pool_;
    Config config_;

    mutable std::mutex mutex_;
    std::vector<ColumnSnapshot> baseline_;
    bool baseline_set_ = false;
    std::vector<DriftEvent> drift_events_;

    std::atomic<bool> running_{false};
    std::atomic<uint64_t> total_drifts_{0};
    std::atomic<uint64_t> checks_performed_{0};
    std::thread worker_;
};

} // namespace sqlproxy
