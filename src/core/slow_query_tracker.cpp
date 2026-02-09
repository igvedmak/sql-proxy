#include "core/slow_query_tracker.hpp"

namespace sqlproxy {

SlowQueryTracker::SlowQueryTracker(const Config& config)
    : config_(config) {}

bool SlowQueryTracker::record_if_slow(const SlowQueryRecord& record) {
    if (!config_.enabled) return false;

    const auto threshold = std::chrono::milliseconds(config_.threshold_ms);
    if (record.execution_time < threshold) return false;

    total_slow_queries_.fetch_add(1, std::memory_order_relaxed);

    std::lock_guard lock(mutex_);
    records_.push_back(record);
    while (records_.size() > config_.max_entries) {
        records_.pop_front();
    }

    return true;
}

std::vector<SlowQueryRecord> SlowQueryTracker::get_recent(size_t limit) const {
    std::lock_guard lock(mutex_);

    if (limit == 0 || limit >= records_.size()) {
        return {records_.begin(), records_.end()};
    }

    const auto start = records_.end() - static_cast<std::ptrdiff_t>(limit);
    return {start, records_.end()};
}

} // namespace sqlproxy
