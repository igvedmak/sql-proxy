#pragma once

#include "db/isql_parser.hpp"
#include "parser/fingerprinter.hpp"
#include "parser/parse_cache.hpp"
#include <memory>
#include <string_view>

namespace sqlproxy {

/**
 * @brief MySQL SQL parser implementing ISqlParser
 *
 * Uses regex-based parsing as an MVP (no libpg_query equivalent for MySQL).
 * Extracts statement type and table names from SQL text.
 *
 * Limitations vs PgSqlParser:
 * - No full AST (can't detect subqueries, aggregation, etc.)
 * - Table extraction may miss complex patterns (CTEs, derived tables)
 * - Statement type detection is keyword-based
 *
 * Future: Could use ANTLR4 with MySQL grammar for full AST support.
 */
class MysqlSqlParser : public ISqlParser {
public:
    explicit MysqlSqlParser(std::shared_ptr<ParseCache> cache = nullptr);
    ~MysqlSqlParser() override = default;

    [[nodiscard]] ParseResult parse(std::string_view sql) override;

    [[nodiscard]] ParseCache::Stats get_cache_stats() const override {
        return cache_ ? cache_->get_stats() : ParseCache::Stats{};
    }

    void clear_cache() override {
        if (cache_) {
            cache_->clear();
        }
    }

private:
    StatementType detect_statement_type(std::string_view sql);
    std::vector<TableRef> extract_tables(std::string_view sql, StatementType type);

    std::shared_ptr<ParseCache> cache_;
};

} // namespace sqlproxy
