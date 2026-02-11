#pragma once

#include <cstdint>
#include <deque>
#include <shared_mutex>
#include <string>
#include <vector>

namespace sqlproxy {

struct ColumnVersionEvent {
    std::string timestamp;
    std::string user;
    std::string database;
    std::string table;
    std::string column;
    std::string operation;  // "INSERT" | "UPDATE" | "DELETE"
    uint64_t fingerprint = 0;
    uint64_t affected_rows = 0;
};

class ColumnVersionTracker {
public:
    struct Config {
        bool enabled = false;
        size_t max_events = 10000;
    };

    ColumnVersionTracker();
    explicit ColumnVersionTracker(Config config);

    [[nodiscard]] bool is_enabled() const { return config_.enabled; }

    void record(const ColumnVersionEvent& event);

    [[nodiscard]] std::vector<ColumnVersionEvent> get_history(
        const std::string& table = "", const std::string& column = "", size_t limit = 100) const;

    [[nodiscard]] size_t total_events() const;

private:
    Config config_;
    std::deque<ColumnVersionEvent> events_;
    mutable std::shared_mutex mutex_;
};

} // namespace sqlproxy
