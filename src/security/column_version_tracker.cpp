#include "security/column_version_tracker.hpp"

#include <mutex>

namespace sqlproxy {

ColumnVersionTracker::ColumnVersionTracker() : ColumnVersionTracker(Config{}) {}

ColumnVersionTracker::ColumnVersionTracker(Config config)
    : config_(std::move(config)) {}

void ColumnVersionTracker::record(const ColumnVersionEvent& event) {
    if (!config_.enabled) return;

    std::unique_lock lock(mutex_);
    events_.push_back(event);
    while (events_.size() > config_.max_events) {
        events_.pop_front();
    }
}

std::vector<ColumnVersionEvent> ColumnVersionTracker::get_history(
    const std::string& table, const std::string& column, size_t limit) const {

    std::shared_lock lock(mutex_);

    std::vector<ColumnVersionEvent> result;
    result.reserve(std::min(limit, events_.size()));

    // Iterate in reverse (newest first)
    for (auto it = events_.rbegin(); it != events_.rend() && result.size() < limit; ++it) {
        if (!table.empty() && it->table != table) continue;
        if (!column.empty() && it->column != column) continue;
        result.push_back(*it);
    }

    return result;
}

size_t ColumnVersionTracker::total_events() const {
    std::shared_lock lock(mutex_);
    return events_.size();
}

} // namespace sqlproxy
