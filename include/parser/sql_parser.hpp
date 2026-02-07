#pragma once

#include "core/types.hpp"
#include "parser/fingerprinter.hpp"
#include "parser/parse_cache.hpp"
#include <string_view>
#include <memory>
#include <system_error>

namespace sqlproxy {

/**
 * @brief SQL Parser - wraps libpg_query (PostgreSQL's parser)
 *
 * Uses PostgreSQL's actual parser extracted as a C library.
 * Same code Postgres uses internally - handles all edge cases.
 *
 * Performance:
 * - Parse time: ~50μs for typical query (on cache miss)
 * - Cache hit: ~500ns (fingerprint + lookup)
 *
 * Thread-safety: Parser is stateless, safe for concurrent use
 */
class SQLParser {
public:
    /**
     * @brief Error category for parse errors
     */
    enum class ErrorCode {
        SUCCESS = 0,
        SYNTAX_ERROR,
        UNSUPPORTED_STATEMENT,
        PARSER_INTERNAL_ERROR,
        EMPTY_QUERY
    };

    /**
     * @brief Parse result
     */
    struct ParseResult {
        bool success;
        ErrorCode error_code;
        std::string error_message;
        std::shared_ptr<StatementInfo> statement_info;

        ParseResult()
            : success(false), error_code(ErrorCode::SUCCESS) {}

        static ParseResult ok(std::shared_ptr<StatementInfo> info) {
            ParseResult result;
            result.success = true;
            result.error_code = ErrorCode::SUCCESS;
            result.statement_info = std::move(info);
            return result;
        }

        static ParseResult error(ErrorCode code, std::string message) {
            ParseResult result;
            result.success = false;
            result.error_code = code;
            result.error_message = std::move(message);
            return result;
        }
    };

    /**
     * @brief Construct parser with optional cache
     * @param cache Parse cache (nullptr = no caching)
     */
    explicit SQLParser(std::shared_ptr<ParseCache> cache = nullptr);

    ~SQLParser() = default;

    /**
     * @brief Parse SQL query
     * @param sql SQL query string
     * @return Parse result with statement info or error
     */
    ParseResult parse(std::string_view sql);

    /**
     * @brief Get cache statistics
     */
    ParseCache::Stats get_cache_stats() const {
        return cache_ ? cache_->get_stats() : ParseCache::Stats{};
    }

    /**
     * @brief Clear parse cache
     */
    void clear_cache() {
        if (cache_) {
            cache_->clear();
        }
    }

private:
    /**
     * @brief Parse SQL using libpg_query (cache miss path)
     * @param sql SQL query
     * @param fingerprint Pre-computed fingerprint
     * @return Parse result
     */
    ParseResult parse_with_libpgquery(std::string_view sql,
                                       const QueryFingerprint& fingerprint);

    /**
     * @brief Extract statement type from libpg_query AST
     * @param parse_result libpg_query parse result
     * @return Statement type
     */
    StatementType extract_statement_type(void* parse_result);

    /**
     * @brief Extract tables from libpg_query AST (basic extraction)
     * @param parse_result libpg_query parse result
     * @return List of table references
     */
    std::vector<TableRef> extract_tables(void* parse_result);

    std::shared_ptr<ParseCache> cache_;
};

} // namespace sqlproxy
