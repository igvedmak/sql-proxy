#include "schema/schema_manager.hpp"

#include <algorithm>

namespace sqlproxy {

SchemaManager::SchemaManager(const SchemaManagementConfig& config)
    : config_(config) {}

bool SchemaManager::intercept_ddl(const std::string& user, const std::string& db,
    const std::string& sql, StatementType type) {
    if (!config_.enabled) return true;
    if (!config_.require_approval) return true;

    // Only intercept DDL statements
    if (!stmt_mask::test(type, stmt_mask::kDDL)) return true;

    // Create pending DDL entry
    PendingDDL pending;
    pending.user = user;
    pending.database = db;
    pending.table = extract_table_from_type(type, sql);
    pending.sql = sql;
    pending.type = type;
    pending.status = std::string{ddl_status::kPending};

    std::unique_lock lock(mutex_);
    pending_.emplace(pending.id, std::move(pending));

    return false;  // Block — requires approval
}

void SchemaManager::record_change(const std::string& user, const std::string& db,
    const std::string& table, const std::string& sql, StatementType type) {
    if (!config_.enabled) return;

    SchemaSnapshot snapshot;
    snapshot.user = user;
    snapshot.database = db;
    snapshot.table = table;
    snapshot.sql = sql;
    snapshot.type = type;
    snapshot.status = std::string{ddl_status::kApplied};

    std::unique_lock lock(mutex_);
    history_.emplace_back(std::move(snapshot));

    // Bounded history
    while (history_.size() > config_.max_history_entries) {
        history_.pop_front();
    }
}

std::vector<PendingDDL> SchemaManager::get_pending() const {
    std::shared_lock lock(mutex_);
    std::vector<PendingDDL> result;
    result.reserve(pending_.size());
    for (const auto& [id, ddl] : pending_) {
        if (ddl.status == ddl_status::kPending) {
            result.push_back(ddl);
        }
    }
    return result;
}

bool SchemaManager::approve(const std::string& id, const std::string& admin) {
    std::unique_lock lock(mutex_);
    auto it = pending_.find(id);
    if (it == pending_.end() || it->second.status != ddl_status::kPending) {
        return false;
    }

    it->second.status = std::string{ddl_status::kApproved};
    it->second.reviewed_by = admin;
    it->second.reviewed_at = std::chrono::system_clock::now();

    // Also record in history
    SchemaSnapshot snapshot;
    snapshot.user = it->second.user;
    snapshot.database = it->second.database;
    snapshot.table = it->second.table;
    snapshot.sql = it->second.sql;
    snapshot.type = it->second.type;
    snapshot.status = std::string{ddl_status::kApproved};

    history_.emplace_back(std::move(snapshot));
    while (history_.size() > config_.max_history_entries) {
        history_.pop_front();
    }

    return true;
}

bool SchemaManager::reject(const std::string& id, const std::string& admin) {
    std::unique_lock lock(mutex_);
    auto it = pending_.find(id);
    if (it == pending_.end() || it->second.status != ddl_status::kPending) {
        return false;
    }

    it->second.status = std::string{ddl_status::kRejected};
    it->second.reviewed_by = admin;
    it->second.reviewed_at = std::chrono::system_clock::now();

    // Record rejection in history
    SchemaSnapshot snapshot;
    snapshot.user = it->second.user;
    snapshot.database = it->second.database;
    snapshot.table = it->second.table;
    snapshot.sql = it->second.sql;
    snapshot.type = it->second.type;
    snapshot.status = std::string{ddl_status::kRejected};

    history_.emplace_back(std::move(snapshot));
    while (history_.size() > config_.max_history_entries) {
        history_.pop_front();
    }

    return true;
}

std::vector<SchemaSnapshot> SchemaManager::get_history(const std::string& db,
    const std::string& table, size_t limit) const {
    std::shared_lock lock(mutex_);
    std::vector<SchemaSnapshot> result;
    result.reserve(std::min(limit, history_.size()));

    // Iterate in reverse (newest first)
    for (auto it = history_.rbegin(); it != history_.rend() && result.size() < limit; ++it) {
        if (!db.empty() && it->database != db) continue;
        if (!table.empty() && it->table != table) continue;
        result.push_back(*it);
    }
    return result;
}

size_t SchemaManager::history_size() const {
    std::shared_lock lock(mutex_);
    return history_.size();
}

size_t SchemaManager::pending_count() const {
    std::shared_lock lock(mutex_);
    size_t count = 0;
    for (const auto& [id, ddl] : pending_) {
        if (ddl.status == ddl_status::kPending) ++count;
    }
    return count;
}

std::string SchemaManager::extract_table_from_type(StatementType /*type*/, const std::string& sql) {
    // Simple heuristic: find table name after CREATE/ALTER/DROP TABLE or CREATE/DROP INDEX
    // Look for common patterns
    auto lower = sql;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // Find "table" keyword and extract the next word
    for (const char* keyword : {"table", "index on"}) {
        auto pos = lower.find(keyword);
        if (pos != std::string::npos) {
            pos += std::string(keyword).size();
            // Skip whitespace and optional "if exists"/"if not exists"
            while (pos < sql.size() && std::isspace(sql[pos])) ++pos;

            // Skip "if exists" / "if not exists"
            if (lower.substr(pos, 9) == "if exists") pos += 9;
            else if (lower.substr(pos, 13) == "if not exists") pos += 13;

            while (pos < sql.size() && std::isspace(sql[pos])) ++pos;

            // Extract identifier
            size_t end = pos;
            while (end < sql.size() && !std::isspace(sql[end]) &&
                   sql[end] != '(' && sql[end] != ';') {
                ++end;
            }
            if (end > pos) {
                return sql.substr(pos, end - pos);
            }
        }
    }

    return "unknown";
}

} // namespace sqlproxy
