#pragma once

#include "core/types.hpp"
#include <string>

namespace sqlproxy {

/**
 * @brief Abstract query executor interface
 *
 * Replaces the concrete QueryExecutor class.
 * Pipeline holds shared_ptr<IQueryExecutor>.
 */
class IQueryExecutor {
public:
    virtual ~IQueryExecutor() = default;

    /**
     * @brief Execute SQL statement
     * @param sql SQL query
     * @param stmt_type Statement type (for branching)
     * @return Query result
     */
    [[nodiscard]] virtual QueryResult execute(
        const std::string& sql, StatementType stmt_type) = 0;
};

} // namespace sqlproxy
