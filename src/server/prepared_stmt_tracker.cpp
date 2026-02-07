#include "server/prepared_stmt_tracker.hpp"

namespace sqlproxy {

void PreparedStatementTracker::register_statement(
    const std::string& user, const std::string& stmt_name,
    PreparedStatementEntry entry) {
    std::unique_lock lock(mutex_);
    statements_[user][stmt_name] = std::move(entry);
}

std::optional<PreparedStatementEntry> PreparedStatementTracker::find_statement(
    const std::string& user, const std::string& stmt_name) const {
    std::shared_lock lock(mutex_);
    const auto user_it = statements_.find(user);
    if (user_it == statements_.end()) return std::nullopt;
    const auto stmt_it = user_it->second.find(stmt_name);
    if (stmt_it == user_it->second.end()) return std::nullopt;
    return stmt_it->second;
}

void PreparedStatementTracker::deallocate_statement(
    const std::string& user, const std::string& stmt_name) {
    std::unique_lock lock(mutex_);
    const auto user_it = statements_.find(user);
    if (user_it != statements_.end()) {
        user_it->second.erase(stmt_name);
        if (user_it->second.empty()) {
            statements_.erase(user_it);
        }
    }
}

void PreparedStatementTracker::deallocate_all(const std::string& user) {
    std::unique_lock lock(mutex_);
    statements_.erase(user);
}

size_t PreparedStatementTracker::total_statements() const {
    std::shared_lock lock(mutex_);
    size_t count = 0;
    for (const auto& [_, user_stmts] : statements_) {
        count += user_stmts.size();
    }
    return count;
}

} // namespace sqlproxy
