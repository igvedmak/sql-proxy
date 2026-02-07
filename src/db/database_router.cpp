#include "db/database_router.hpp"

namespace sqlproxy {

void DatabaseRouter::register_executor(const std::string& db_name,
                                        std::shared_ptr<IQueryExecutor> executor) {
    std::unique_lock lock(mutex_);
    executors_[db_name] = std::move(executor);
}

void DatabaseRouter::register_parser(const std::string& db_name,
                                      std::shared_ptr<ISqlParser> parser) {
    std::unique_lock lock(mutex_);
    parsers_[db_name] = std::move(parser);
}

std::shared_ptr<IQueryExecutor> DatabaseRouter::get_executor(const std::string& db_name) const {
    std::shared_lock lock(mutex_);
    const auto it = executors_.find(db_name);
    if (it != executors_.end()) return it->second;
    return nullptr;
}

std::shared_ptr<ISqlParser> DatabaseRouter::get_parser(const std::string& db_name) const {
    std::shared_lock lock(mutex_);
    const auto it = parsers_.find(db_name);
    if (it != parsers_.end()) return it->second;
    return nullptr;
}

bool DatabaseRouter::has_database(const std::string& db_name) const {
    std::shared_lock lock(mutex_);
    return executors_.contains(db_name);
}

std::vector<std::string> DatabaseRouter::database_names() const {
    std::shared_lock lock(mutex_);
    std::vector<std::string> names;
    names.reserve(executors_.size());
    for (const auto& [name, _] : executors_) {
        names.push_back(name);
    }
    return names;
}

} // namespace sqlproxy
