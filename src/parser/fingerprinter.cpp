#include "parser/fingerprinter.hpp"
#include "core/utils.hpp"

// xxHash64 - include from third_party
#define XXH_INLINE_ALL
#include "xxhash.h"

#include <algorithm>
#include <cctype>
#include <unordered_set>

namespace sqlproxy {

// ============================================================================
// Lookup table for character classification — eliminates locale-dependent
// std::isdigit/isalpha/isalnum/ispunct/tolower calls (each ~5-10ns with locale)
// Single 256-byte table gives O(1) classification + lowercase in one load.
// ============================================================================
namespace {

enum CharClass : uint8_t {
    CC_OTHER   = 0,
    CC_SPACE   = 1,
    CC_DIGIT   = 2,
    CC_ALPHA   = 4,
    CC_IDENT   = 8,   // _ and $
    CC_PUNCT   = 16,
};

struct CharTable {
    uint8_t cls[256];
    char    lower[256];

    constexpr CharTable() : cls{}, lower{} {
        for (int i = 0; i < 256; ++i) {
            lower[i] = static_cast<char>(i);
            cls[i] = CC_OTHER;
        }
        cls[' '] = CC_SPACE; cls['\t'] = CC_SPACE;
        cls['\n'] = CC_SPACE; cls['\r'] = CC_SPACE;
        for (int i = '0'; i <= '9'; ++i) cls[i] = CC_DIGIT;
        for (int i = 'a'; i <= 'z'; ++i) cls[i] = CC_ALPHA;
        for (int i = 'A'; i <= 'Z'; ++i) {
            cls[i] = CC_ALPHA;
            lower[i] = static_cast<char>(i + 32);
        }
        cls['_'] = CC_IDENT;
        cls['$'] = CC_IDENT;
        // Punctuation
        cls['!'] = CC_PUNCT; cls['"'] = CC_PUNCT; cls['#'] = CC_PUNCT;
        cls['%'] = CC_PUNCT; cls['&'] = CC_PUNCT; cls['\''] = CC_PUNCT;
        cls['('] = CC_PUNCT; cls[')'] = CC_PUNCT; cls['*'] = CC_PUNCT;
        cls['+'] = CC_PUNCT; cls[','] = CC_PUNCT; cls['-'] = CC_PUNCT;
        cls['.'] = CC_PUNCT; cls['/'] = CC_PUNCT; cls[':'] = CC_PUNCT;
        cls[';'] = CC_PUNCT; cls['<'] = CC_PUNCT; cls['='] = CC_PUNCT;
        cls['>'] = CC_PUNCT; cls['?'] = CC_PUNCT; cls['@'] = CC_PUNCT;
        cls['['] = CC_PUNCT; cls['\\'] = CC_PUNCT; cls[']'] = CC_PUNCT;
        cls['^'] = CC_PUNCT; cls['`'] = CC_PUNCT; cls['{'] = CC_PUNCT;
        cls['|'] = CC_PUNCT; cls['}'] = CC_PUNCT; cls['~'] = CC_PUNCT;
    }
};

static constexpr CharTable CT{};

inline bool ct_space(unsigned char c)      { return CT.cls[c] == CC_SPACE; }
inline bool ct_digit(unsigned char c)      { return CT.cls[c] == CC_DIGIT; }
inline bool ct_ident_start(unsigned char c) { auto v = CT.cls[c]; return v == CC_ALPHA || v == CC_IDENT; }
inline bool ct_ident_cont(unsigned char c)  { auto v = CT.cls[c]; return v == CC_ALPHA || v == CC_DIGIT || v == CC_IDENT; }
inline bool ct_punct(unsigned char c)      { return CT.cls[c] == CC_PUNCT; }
inline char ct_lower(unsigned char c)      { return CT.lower[c]; }

} // anonymous namespace

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

    const size_t len = sql.size();
    for (size_t i = 0; i < len; ++i) {
        const auto c = static_cast<unsigned char>(sql[i]);
        const auto next_c = (i + 1 < len) ? static_cast<unsigned char>(sql[i + 1]) : static_cast<unsigned char>('\0');

        switch (state) {
            case State::NORMAL: {
                // Check for comment start
                if (c == '/' && next_c == '*') {
                    state = State::IN_BLOCK_COMMENT;
                    ++i;
                    break;
                }
                if (c == '-' && next_c == '-') {
                    state = State::IN_LINE_COMMENT;
                    ++i;
                    break;
                }

                // Check for string literal
                if (c == '\'') {
                    state = State::IN_SINGLE_QUOTE;
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
                    if (!last_was_whitespace && !result.empty()) {
                        result += ' ';
                    }
                    result += '"';
                    last_was_whitespace = false;
                    break;
                }

                // Check for numeric literal
                if (ct_digit(c) || (c == '.' && ct_digit(next_c))) {
                    state = State::IN_NUMBER;
                    if (!last_was_whitespace && !result.empty() && result.back() != '(') {
                        result += ' ';
                    }
                    result += '?';
                    last_was_whitespace = false;
                    break;
                }

                // Check for identifier/keyword start
                if (ct_ident_start(c)) {
                    state = State::IN_IDENTIFIER;
                    current_word.clear();
                    current_word += ct_lower(c);
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
                if (ct_space(c)) {
                    if (!last_was_whitespace && !result.empty()) {
                        result += ' ';
                        last_was_whitespace = true;
                    }
                    break;
                }

                // Other characters (operators, punctuation)
                if (!last_was_whitespace && !result.empty() &&
                    !ct_punct(static_cast<unsigned char>(result.back()))) {
                    result += ' ';
                }
                result += static_cast<char>(c);
                last_was_whitespace = false;
                break;
            }

            case State::IN_IDENTIFIER: {
                if (ct_ident_cont(c)) {
                    current_word += ct_lower(c);
                } else {
                    // End of identifier - flush it
                    if (!last_was_whitespace && !result.empty()) {
                        result += ' ';
                    }
                    result += current_word;

                    // Check if this is "IN" keyword
                    if (current_word.size() == 2 && current_word[0] == 'i' && current_word[1] == 'n') {
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
                if (!ct_digit(c) && c != '.' && c != 'e' && c != 'E' &&
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
                    if (next_c == '\'') {
                        ++i;
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
                    result += ct_lower(c);
                }
                break;
            }

            case State::IN_BLOCK_COMMENT: {
                if (c == '*' && next_c == '/') {
                    state = State::NORMAL;
                    ++i;
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
                if (c == '(') {
                    ++paren_depth;
                } else if (c == ')') {
                    --paren_depth;
                    if (paren_depth < in_list_paren_depth) {
                        state = State::NORMAL;
                        in_in_clause = false;
                        in_list_paren_depth = 0;
                        --i;
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
    return ct_space(static_cast<unsigned char>(c));
}

bool QueryFingerprinter::is_identifier_start(char c) {
    return ct_ident_start(static_cast<unsigned char>(c));
}

bool QueryFingerprinter::is_identifier_continue(char c) {
    return ct_ident_cont(static_cast<unsigned char>(c));
}

bool QueryFingerprinter::is_digit(char c) {
    return ct_digit(static_cast<unsigned char>(c));
}

bool QueryFingerprinter::is_keyword(std::string_view word) {
    return SQL_KEYWORDS.contains(word);
}

} // namespace sqlproxy
