#pragma once

#include "core/types.hpp"
#include "parser/parse_cache.hpp"
#include <string_view>
#include <memory>
#include <string>

namespace sqlproxy {

/**
 * @brief Abstract SQL parser interface
 *
 * Each database backend provides its own parser
 * (libpg_query for PostgreSQL, regex/ANTLR for MySQL, etc.).
 */
class ISqlParser {
public:
    virtual ~ISqlParser() = default;

    enum class ErrorCode {
        SUCCESS = 0,
        SYNTAX_ERROR,
        UNSUPPORTED_STATEMENT,
        PARSER_INTERNAL_ERROR,
        EMPTY_QUERY
    };

    struct ParseResult {
        bool success;
        ErrorCode error_code;
        std::string error_message;
        std::shared_ptr<StatementInfo> statement_info;

        ParseResult() : success(false), error_code(ErrorCode::SUCCESS) {}

        static ParseResult ok(std::shared_ptr<StatementInfo> info) {
            ParseResult r;
            r.success = true;
            r.error_code = ErrorCode::SUCCESS;
            r.statement_info = std::move(info);
            return r;
        }

        static ParseResult error(ErrorCode code, std::string message) {
            ParseResult r;
            r.success = false;
            r.error_code = code;
            r.error_message = std::move(message);
            return r;
        }
    };

    /**
     * @brief Parse SQL query
     * @param sql SQL query string
     * @return Parse result with statement info or error
     */
    [[nodiscard]] virtual ParseResult parse(std::string_view sql) = 0;

    /**
     * @brief Get cache statistics
     */
    [[nodiscard]] virtual ParseCache::Stats get_cache_stats() const = 0;

    /**
     * @brief Clear parse cache
     */
    virtual void clear_cache() = 0;
};

} // namespace sqlproxy
