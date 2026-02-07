#pragma once

#include "core/types.hpp"
#include "parser/parse_cache.hpp"
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace sqlproxy {

/**
 * @brief Entry for a tracked prepared statement
 */
struct PreparedStatementEntry {
    std::string name;
    std::string original_sql;
    std::shared_ptr<StatementInfo> parsed_info;
    std::vector<std::string> param_types;
};

/**
 * @brief Per-user tracking of prepared statements
 *
 * Thread-safe via shared_mutex. Maps user → (stmt_name → entry).
 */
class PreparedStatementTracker {
public:
    void register_statement(const std::string& user, const std::string& stmt_name,
                            PreparedStatementEntry entry);

    [[nodiscard]] std::optional<PreparedStatementEntry> find_statement(
        const std::string& user, const std::string& stmt_name) const;

    void deallocate_statement(const std::string& user, const std::string& stmt_name);
    void deallocate_all(const std::string& user);

    [[nodiscard]] size_t total_statements() const;

private:
    // user → (stmt_name → entry)
    std::unordered_map<std::string,
        std::unordered_map<std::string, PreparedStatementEntry>> statements_;
    mutable std::shared_mutex mutex_;
};

} // namespace sqlproxy
