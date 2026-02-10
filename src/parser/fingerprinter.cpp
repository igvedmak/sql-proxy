#include "parser/fingerprinter.hpp"
#include "core/utils.hpp"

// xxHash64 - include from third_party
#define XXH_INLINE_ALL
#include "xxhash.h"

#include <algorithm>
#include <cctype>
#include <unordered_set>

namespace sqlproxy {

// Transparent hash/equal for heterogeneous lookup (avoids temporary std::string from string_view)
struct StringViewHash {
    using is_transparent = void;
    size_t operator()(std::string_view sv) const noexcept {
        return std::hash<std::string_view>{}(sv);
    }
};
struct StringViewEqual {
    using is_transparent = void;
    bool operator()(std::string_view a, std::string_view b) const noexcept {
        return a == b;
    }
};

// SQL keywords that should be lowercased (not exhaustive, most common ones)
static const std::unordered_set<std::string, StringViewHash, StringViewEqual> SQL_KEYWORDS = {
    "select", "from", "where", "and", "or", "not", "in", "between", "like",
    "is", "null", "true", "false", "insert", "into", "values", "update",
    "set", "delete", "join", "inner", "outer", "left", "right", "full",
    "cross", "on", "using", "group", "by", "having", "order", "asc", "desc",
    "limit", "offset", "union", "all", "distinct", "as", "exists", "case",
    "when", "then", "else", "end", "cast", "extract", "substring", "trim",
    "create", "alter", "drop", "table", "index", "view", "database", "schema"
};

QueryFingerprint QueryFingerprinter::fingerprint(std::string_view sql) {
    std::string normalized = normalize(sql);
    uint64_t hash = compute_hash(normalized);
    return QueryFingerprint(hash, std::move(normalized));
}

std::string QueryFingerprinter::normalize(std::string_view sql) {
    std::string result;
    result.reserve(sql.size()); // Pre-allocate (may be smaller after normalization)

    State state = State::NORMAL;
    State prev_state = State::NORMAL;

    bool last_was_whitespace = true;  // Start true to avoid leading whitespace
    bool in_in_clause = false;
    int paren_depth = 0;
    int in_list_paren_depth = 0;

    std::string current_word;
    current_word.reserve(64);

    for (size_t i = 0; i < sql.size(); ++i) {
        const char c = sql[i];
        const char next_c = (i + 1 < sql.size()) ? sql[i + 1] : '\0';

        switch (state) {
            case State::NORMAL: {
                // Check for comment start
                if (c == '/' && next_c == '*') {
                    state = State::IN_BLOCK_COMMENT;
                    ++i; // Skip next char
                    break;
                }
                if (c == '-' && next_c == '-') {
                    state = State::IN_LINE_COMMENT;
                    ++i; // Skip next char
                    break;
                }

                // Check for string literal
                if (c == '\'') {
                    state = State::IN_SINGLE_QUOTE;
                    // Replace entire string literal with ?
                    if (!last_was_whitespace && !result.empty() && result.back() != '(') {
                        result += ' ';
                    }
                    result += '?';
                    last_was_whitespace = false;
                    break;
                }

                // Check for quoted identifier
                if (c == '"') {
                    state = State::IN_DOUBLE_QUOTE;
                    // Keep quoted identifiers as-is (lowercase)
                    if (!last_was_whitespace && !result.empty()) {
                        result += ' ';
                    }
                    result += '"';
                    last_was_whitespace = false;
                    break;
                }

                // Check for numeric literal
                if (is_digit(c) || (c == '.' && is_digit(next_c))) {
                    state = State::IN_NUMBER;
                    // Replace numeric literal with ?
                    if (!last_was_whitespace && !result.empty() && result.back() != '(') {
                        result += ' ';
                    }
                    result += '?';
                    last_was_whitespace = false;
                    break;
                }

                // Check for identifier/keyword start
                if (is_identifier_start(c)) {
                    state = State::IN_IDENTIFIER;
                    current_word.clear();
                    current_word += std::tolower(static_cast<unsigned char>(c));
                    break;
                }

                // Parentheses tracking for IN-list detection
                if (c == '(') {
                    ++paren_depth;
                    if (in_in_clause && paren_depth == in_list_paren_depth + 1) {
                        state = State::IN_IN_LIST;
                        in_list_paren_depth = paren_depth;
                        if (!last_was_whitespace && !result.empty()) {
                            result += ' ';
                        }
                        result += "(?)";
                        last_was_whitespace = false;
                        break;
                    }
                }
                if (c == ')') {
                    --paren_depth;
                    if (paren_depth < in_list_paren_depth) {
                        in_in_clause = false;
                        in_list_paren_depth = 0;
                    }
                }

                // Whitespace - collapse to single space
                if (is_whitespace(c)) {
                    if (!last_was_whitespace && !result.empty()) {
                        result += ' ';
                        last_was_whitespace = true;
                    }
                    break;
                }

                // Other characters (operators, punctuation)
                if (!last_was_whitespace && !result.empty() &&
                    !std::ispunct(static_cast<unsigned char>(result.back()))) {
                    result += ' ';
                }
                result += c;
                last_was_whitespace = false;
                break;
            }

            case State::IN_IDENTIFIER: {
                if (is_identifier_continue(c)) {
                    current_word += std::tolower(static_cast<unsigned char>(c));
                } else {
                    // End of identifier - flush it
                    if (!last_was_whitespace && !result.empty()) {
                        result += ' ';
                    }
                    result += current_word;

                    // Check if this is "IN" keyword
                    if (current_word == "in") {
                        in_in_clause = true;
                        in_list_paren_depth = paren_depth;
                    }

                    last_was_whitespace = false;
                    state = State::NORMAL;
                    --i; // Re-process current character
                    current_word.clear();
                }
                break;
            }

            case State::IN_NUMBER: {
                // Skip numeric literal
                if (!is_digit(c) && c != '.' && c != 'e' && c != 'E' &&
                    c != '+' && c != '-') {
                    state = State::NORMAL;
                    --i; // Re-process current character
                }
                break;
            }

            case State::IN_SINGLE_QUOTE: {
                if (c == '\\') {
                    state = State::ESCAPE;
                    prev_state = State::IN_SINGLE_QUOTE;
                } else if (c == '\'') {
                    // Check for escaped quote ''
                    if (next_c == '\'') {
                        ++i; // Skip next quote
                    } else {
                        state = State::NORMAL;
                    }
                }
                break;
            }

            case State::IN_DOUBLE_QUOTE: {
                if (c == '\\') {
                    state = State::ESCAPE;
                    prev_state = State::IN_DOUBLE_QUOTE;
                } else if (c == '"') {
                    result += '"';
                    state = State::NORMAL;
                } else {
                    result += std::tolower(static_cast<unsigned char>(c));
                }
                break;
            }

            case State::IN_BLOCK_COMMENT: {
                if (c == '*' && next_c == '/') {
                    state = State::NORMAL;
                    ++i; // Skip next char
                    // Add space to prevent tokens from merging
                    if (!last_was_whitespace && !result.empty()) {
                        result += ' ';
                        last_was_whitespace = true;
                    }
                }
                break;
            }

            case State::IN_LINE_COMMENT: {
                if (c == '\n' || c == '\r') {
                    state = State::NORMAL;
                    if (!last_was_whitespace && !result.empty()) {
                        result += ' ';
                        last_was_whitespace = true;
                    }
                }
                break;
            }

            case State::IN_IN_LIST: {
                // Skip everything inside IN (...) list until matching )
                if (c == '(') {
                    ++paren_depth;
                } else if (c == ')') {
                    --paren_depth;
                    if (paren_depth < in_list_paren_depth) {
                        state = State::NORMAL;
                        in_in_clause = false;
                        in_list_paren_depth = 0;
                        --i; // Re-process closing paren
                    }
                }
                break;
            }

            case State::ESCAPE: {
                state = prev_state;
                break;
            }
        }
    }

    // Flush any remaining identifier
    if (state == State::IN_IDENTIFIER && !current_word.empty()) {
        if (!last_was_whitespace && !result.empty()) {
            result += ' ';
        }
        result += current_word;
    }

    // Trim trailing whitespace
    while (!result.empty() && result.back() == ' ') {
        result.pop_back();
    }

    return result;
}

uint64_t QueryFingerprinter::compute_hash(std::string_view data) {
    return XXH64(data.data(), data.size(), 0);
}

bool QueryFingerprinter::is_whitespace(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

bool QueryFingerprinter::is_identifier_start(char c) {
    return std::isalpha(static_cast<unsigned char>(c)) || c == '_';
}

bool QueryFingerprinter::is_identifier_continue(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$';
}

bool QueryFingerprinter::is_digit(char c) {
    return std::isdigit(static_cast<unsigned char>(c));
}

bool QueryFingerprinter::is_keyword(std::string_view word) {
    // O(1) lookup without creating temporary std::string (transparent hash)
    return SQL_KEYWORDS.contains(word);
}

} // namespace sqlproxy
