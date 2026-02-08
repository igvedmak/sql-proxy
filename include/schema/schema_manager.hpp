#pragma once

#include "core/types.hpp"
#include <chrono>
#include <deque>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace sqlproxy {

struct SchemaManagementConfig {
    bool enabled = false;
    bool require_approval = false;
    size_t max_history_entries = 1000;
};

struct SchemaSnapshot {
    std::string id;         // UUID
    std::string user;
    std::string database;
    std::string table;
    std::string sql;
    StatementType type;
    std::chrono::system_clock::time_point timestamp;
    std::string status;     // "applied", "pending", "rejected"
};

struct PendingDDL {
    std::string id;         // UUID
    std::string user;
    std::string database;
    std::string table;
    std::string sql;
    StatementType type;
    std::chrono::system_clock::time_point submitted_at;
    std::string status;     // "pending", "approved", "rejected"
    std::string reviewed_by;
    std::chrono::system_clock::time_point reviewed_at;
};

class SchemaManager {
public:
    explicit SchemaManager(const SchemaManagementConfig& config);

    // Layer 4.1: Returns true if DDL can proceed, false if it requires approval (blocks query)
    [[nodiscard]] bool intercept_ddl(const std::string& user, const std::string& db,
        const std::string& sql, StatementType type);

    // After successful DDL execution, record the change
    void record_change(const std::string& user, const std::string& db,
        const std::string& table, const std::string& sql, StatementType type);

    // Admin APIs
    [[nodiscard]] std::vector<PendingDDL> get_pending() const;
    [[nodiscard]] bool approve(const std::string& id, const std::string& admin);
    [[nodiscard]] bool reject(const std::string& id, const std::string& admin);
    [[nodiscard]] std::vector<SchemaSnapshot> get_history(const std::string& db = "",
        const std::string& table = "", size_t limit = 50) const;
    [[nodiscard]] size_t history_size() const;
    [[nodiscard]] size_t pending_count() const;

    [[nodiscard]] const SchemaManagementConfig& config() const { return config_; }

private:
    // Extract table name from DDL statement type
    static std::string extract_table_from_type(StatementType type, const std::string& sql);

    SchemaManagementConfig config_;
    mutable std::shared_mutex mutex_;
    std::deque<SchemaSnapshot> history_;
    std::unordered_map<std::string, PendingDDL> pending_;
};

} // namespace sqlproxy
