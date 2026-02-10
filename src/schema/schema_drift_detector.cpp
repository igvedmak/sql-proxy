#include "schema/schema_drift_detector.hpp"
#include "core/utils.hpp"
#include "db/pooled_connection.hpp"
#include <algorithm>
#include <format>

namespace sqlproxy {

SchemaDriftDetector::SchemaDriftDetector(
    std::shared_ptr<IConnectionPool> pool, Config config)
    : pool_(std::move(pool)), config_(std::move(config)) {}

SchemaDriftDetector::~SchemaDriftDetector() {
    stop();
}

void SchemaDriftDetector::start() {
    if (!config_.enabled || running_.load()) return;
    running_.store(true);
    worker_ = std::thread([this] { run_loop(); });
    utils::log::info(std::format("Schema drift detector: started (interval={}s, schema={})",
        config_.check_interval_seconds, config_.schema_name));
}

void SchemaDriftDetector::stop() {
    running_.store(false);
    if (worker_.joinable()) {
        worker_.join();
    }
}

std::vector<SchemaDriftDetector::DriftEvent> SchemaDriftDetector::get_drift_events() const {
    std::lock_guard lock(mutex_);
    return drift_events_;
}

void SchemaDriftDetector::run_loop() {
    while (running_.load()) {
        try {
            auto current = fetch_current_schema();
            if (!current.empty()) {
                detect_drift(current);
                checks_performed_.fetch_add(1, std::memory_order_relaxed);
            }
        } catch (const std::exception& e) {
            utils::log::warn(std::format("Schema drift check failed: {}", e.what()));
        }

        // Sleep with periodic wake-up to check running_ flag
        for (int i = 0; i < config_.check_interval_seconds && running_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

std::vector<SchemaDriftDetector::ColumnSnapshot> SchemaDriftDetector::fetch_current_schema() const {
    std::vector<ColumnSnapshot> result;

    if (!pool_) return result;

    const auto conn_handle = pool_->acquire(std::chrono::milliseconds{5000});
    if (!conn_handle || !conn_handle->is_valid()) return result;

    const std::string sql = std::format(
        "SELECT table_name, column_name, data_type, is_nullable "
        "FROM information_schema.columns "
        "WHERE table_schema = '{}' "
        "ORDER BY table_name, ordinal_position",
        config_.schema_name);

    const auto db_result = conn_handle->get()->execute(sql);
    if (!db_result.success || db_result.rows.empty()) {
        return result;
    }

    result.reserve(db_result.rows.size());
    for (const auto& row : db_result.rows) {
        if (row.size() < 4) continue;
        ColumnSnapshot col;
        col.table_name = row[0];
        col.column_name = row[1];
        col.data_type = row[2];
        col.is_nullable = (row[3] == "YES");
        result.emplace_back(std::move(col));
    }

    return result;
}

void SchemaDriftDetector::detect_drift(const std::vector<ColumnSnapshot>& current) {
    std::lock_guard lock(mutex_);

    if (!baseline_set_) {
        // First run: set baseline
        baseline_ = current;
        baseline_set_ = true;
        utils::log::info(std::format("Schema drift: baseline set ({} columns)", current.size()));
        return;
    }

    // Build lookup maps: "table.column" -> snapshot
    std::unordered_map<std::string, const ColumnSnapshot*> baseline_map;
    for (const auto& col : baseline_) {
        baseline_map[col.table_name + "." + col.column_name] = &col;
    }

    std::unordered_map<std::string, const ColumnSnapshot*> current_map;
    for (const auto& col : current) {
        current_map[col.table_name + "." + col.column_name] = &col;
    }

    const auto now = utils::format_timestamp(std::chrono::system_clock::now());

    // Check for added or altered columns
    for (const auto& [key, cur] : current_map) {
        const auto it = baseline_map.find(key);
        if (it == baseline_map.end()) {
            // New column
            DriftEvent event;
            event.timestamp = now;
            event.change_type = "COLUMN_ADDED";
            event.table_name = cur->table_name;
            event.column_name = cur->column_name;
            event.new_type = cur->data_type;
            drift_events_.emplace_back(std::move(event));
            total_drifts_.fetch_add(1, std::memory_order_relaxed);
        } else if (it->second->data_type != cur->data_type) {
            // Type changed
            DriftEvent event;
            event.timestamp = now;
            event.change_type = "COLUMN_ALTERED";
            event.table_name = cur->table_name;
            event.column_name = cur->column_name;
            event.old_type = it->second->data_type;
            event.new_type = cur->data_type;
            drift_events_.emplace_back(std::move(event));
            total_drifts_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // Check for dropped columns
    for (const auto& [key, base] : baseline_map) {
        if (!current_map.contains(key)) {
            DriftEvent event;
            event.timestamp = now;
            event.change_type = "COLUMN_DROPPED";
            event.table_name = base->table_name;
            event.column_name = base->column_name;
            event.old_type = base->data_type;
            drift_events_.emplace_back(std::move(event));
            total_drifts_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // Cap drift events at 1000
    if (drift_events_.size() > 1000) {
        drift_events_.erase(drift_events_.begin(),
            drift_events_.begin() + static_cast<long>(drift_events_.size() - 1000));
    }

    // Update baseline to current
    baseline_ = current;
}

} // namespace sqlproxy
