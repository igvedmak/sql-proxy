#include "security/lineage_tracker.hpp"

#include <format>
#include <mutex>

namespace sqlproxy {

LineageTracker::LineageTracker(const Config& config)
    : config_(config) {}

void LineageTracker::record(const LineageEvent& event) {
    if (!config_.enabled) return;

    std::unique_lock lock(mutex_);

    // Add to events deque
    events_.push_back(event);
    while (events_.size() > config_.max_events) {
        events_.pop_front();
    }

    // Update summary
    std::string key;
    key.reserve(event.database.size() + 1 + event.table.size() + 1 + event.column.size());
    key = event.database;
    key += '.';
    key += event.table;
    key += '.';
    key += event.column;

    auto [it, inserted] = summaries_.try_emplace(key, LineageSummary{});
    auto& summary = it->second;
    if (inserted) {
        summary.column_key = key;
        summary.classification = event.classification;
        summary.first_access = std::chrono::system_clock::now();
    }

    ++summary.total_accesses;
    if (event.was_masked) {
        ++summary.masked_accesses;
    } else {
        ++summary.unmasked_accesses;
    }
    summary.accessing_users.insert(event.user);
    summary.last_access = std::chrono::system_clock::now();
}

std::vector<LineageSummary> LineageTracker::get_summaries() const {
    std::shared_lock lock(mutex_);
    std::vector<LineageSummary> result;
    result.reserve(summaries_.size());
    for (const auto& [key, summary] : summaries_) {
        result.push_back(summary);
    }
    return result;
}

std::vector<LineageEvent> LineageTracker::get_events(
    const std::string& user,
    const std::string& table,
    size_t limit) const {

    std::shared_lock lock(mutex_);
    std::vector<LineageEvent> result;
    result.reserve(std::min(limit, events_.size()));

    // Iterate from newest to oldest
    for (auto it = events_.rbegin(); it != events_.rend() && result.size() < limit; ++it) {
        if (!user.empty() && it->user != user) continue;
        if (!table.empty() && it->table != table) continue;
        result.push_back(*it);
    }
    return result;
}

size_t LineageTracker::total_events() const {
    std::shared_lock lock(mutex_);
    return events_.size();
}

} // namespace sqlproxy
