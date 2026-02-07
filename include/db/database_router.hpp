#pragma once

#include "db/iquery_executor.hpp"
#include "db/isql_parser.hpp"
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace sqlproxy {

/**
 * @brief Routes requests to the correct database executor/parser by name
 *
 * Thread-safe via shared_mutex (read-heavy: lookups >> registrations).
 */
class DatabaseRouter {
public:
    void register_executor(const std::string& db_name, std::shared_ptr<IQueryExecutor> executor);
    void register_parser(const std::string& db_name, std::shared_ptr<ISqlParser> parser);

    [[nodiscard]] std::shared_ptr<IQueryExecutor> get_executor(const std::string& db_name) const;
    [[nodiscard]] std::shared_ptr<ISqlParser> get_parser(const std::string& db_name) const;

    [[nodiscard]] bool has_database(const std::string& db_name) const;
    [[nodiscard]] std::vector<std::string> database_names() const;

private:
    std::unordered_map<std::string, std::shared_ptr<IQueryExecutor>> executors_;
    std::unordered_map<std::string, std::shared_ptr<ISqlParser>> parsers_;
    mutable std::shared_mutex mutex_;
};

} // namespace sqlproxy
