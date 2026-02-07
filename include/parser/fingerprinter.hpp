#pragma once

#include "core/types.hpp"
#include <string>
#include <string_view>
#include <cstdint>

namespace sqlproxy {

/**
 * @brief Query fingerprinter - single-pass SQL normalization
 *
 * Transforms SQL queries into canonical form for caching:
 * - Strip comments (block and line -- '\n')
 * - Normalize literals: strings → ?, numbers → ?, booleans → ?
 * - Collapse IN-lists: IN (1,2,3,4,5) → IN (?)
 * - Collapse whitespace
 * - Lowercase keywords
 * - Compute xxHash64 of normalized query
 *
 * Performance: ~300ns for typical query (single pass, no allocations except result)
 *
 * Example:
 *   Input:  "SELECT * FROM users WHERE id IN (1, 2, 3) AND name = 'John'"
 *   Output: "select * from users where id in (?) and name = ?"
 *   Hash:   0x1234567890abcdef
 */
class QueryFingerprinter {
public:
    /**
     * @brief Compute fingerprint of SQL query
     * @param sql Raw SQL query string
     * @return QueryFingerprint with normalized query and xxHash64
     */
    static QueryFingerprint fingerprint(std::string_view sql);

private:
    /**
     * @brief State machine states
     */
    enum class State {
        NORMAL,              // Normal SQL text
        IN_SINGLE_QUOTE,     // Inside 'string literal'
        IN_DOUBLE_QUOTE,     // Inside "identifier" or "string"
        IN_BLOCK_COMMENT,    // Inside /* block comment */
        IN_LINE_COMMENT,     // Inside -- line comment
        IN_NUMBER,           // Inside numeric literal
        IN_IDENTIFIER,       // Inside unquoted identifier/keyword
        IN_IN_LIST,          // Inside IN (...) list
        ESCAPE               // Next char is escaped
    };

    /**
     * @brief Check if character is SQL whitespace
     */
    static bool is_whitespace(char c);

    /**
     * @brief Check if character can start an identifier
     */
    static bool is_identifier_start(char c);

    /**
     * @brief Check if character can continue an identifier
     */
    static bool is_identifier_continue(char c);

    /**
     * @brief Check if character is a digit
     */
    static bool is_digit(char c);

    /**
     * @brief Check if keyword should be normalized (not a data literal)
     */
    static bool is_keyword(std::string_view word);

    /**
     * @brief Normalize SQL query (single pass)
     * @param sql Input SQL
     * @return Normalized SQL string
     */
    static std::string normalize(std::string_view sql);

    /**
     * @brief Compute xxHash64 of string
     * @param data Input data
     * @return 64-bit hash
     */
    static uint64_t compute_hash(std::string_view data);
};

} // namespace sqlproxy
