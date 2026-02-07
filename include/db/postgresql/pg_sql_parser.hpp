#pragma once

#include "db/isql_parser.hpp"
#include "parser/fingerprinter.hpp"
#include "parser/parse_cache.hpp"
#include <memory>
#include <string_view>

namespace sqlproxy {

/**
 * @brief PostgreSQL SQL parser implementing ISqlParser
 *
 * Wraps libpg_query (PostgreSQL's actual parser extracted as a C library).
 * Same code Postgres uses internally - handles all edge cases.
 *
 * Performance:
 * - Parse time: ~50us for typical query (on cache miss)
 * - Cache hit: ~500ns (fingerprint + lookup)
 *
 * Thread-safety: Parser is stateless, safe for concurrent use
 */
class PgSqlParser : public ISqlParser {
public:
    explicit PgSqlParser(std::shared_ptr<ParseCache> cache = nullptr);
    ~PgSqlParser() override = default;

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
    ParseResult parse_with_libpgquery(std::string_view sql,
                                       const QueryFingerprint& fingerprint);

    StatementType extract_statement_type(void* parse_result);
    std::vector<TableRef> extract_tables(void* parse_result);

    std::shared_ptr<ParseCache> cache_;
};

} // namespace sqlproxy
