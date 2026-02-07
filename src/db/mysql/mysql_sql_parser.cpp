#include "db/mysql/mysql_sql_parser.hpp"
#include "core/utils.hpp"

#include <algorithm>
#include <cctype>
#include <regex>
#include <unordered_map>

namespace sqlproxy {

// Keyword-based statement type detection
static const std::unordered_map<std::string, StatementType> MYSQL_STMT_KEYWORDS = {
    {"select", StatementType::SELECT},
    {"insert", StatementType::INSERT},
    {"update", StatementType::UPDATE},
    {"delete", StatementType::DELETE},
    {"create", StatementType::CREATE_TABLE},
    {"alter", StatementType::ALTER_TABLE},
    {"drop", StatementType::DROP_TABLE},
    {"truncate", StatementType::TRUNCATE},
    {"begin", StatementType::BEGIN},
    {"start", StatementType::BEGIN},  // START TRANSACTION
    {"commit", StatementType::COMMIT},
    {"rollback", StatementType::ROLLBACK},
    {"set", StatementType::SET},
    {"show", StatementType::SHOW},
};

MysqlSqlParser::MysqlSqlParser(std::shared_ptr<ParseCache> cache)
    : cache_(std::move(cache)) {}

ISqlParser::ParseResult MysqlSqlParser::parse(std::string_view sql) {
    std::string trimmed_sql = utils::trim(std::string(sql));
    if (trimmed_sql.empty()) {
        return ParseResult::error(ErrorCode::EMPTY_QUERY, "Empty SQL query");
    }

    // Compute fingerprint
    QueryFingerprint fingerprint = QueryFingerprinter::fingerprint(trimmed_sql);

    // Try cache first
    if (cache_) {
        auto cached = cache_->get(fingerprint);
        if (cached.has_value()) {
            return ParseResult::ok(*cached);
        }
    }

    // Detect statement type
    StatementType stmt_type = detect_statement_type(trimmed_sql);
    if (stmt_type == StatementType::UNKNOWN) {
        return ParseResult::error(
            ErrorCode::UNSUPPORTED_STATEMENT,
            "Unsupported or unrecognized statement type");
    }

    // Build ParsedQuery
    ParsedQuery parsed;
    parsed.type = stmt_type;
    parsed.tables = extract_tables(trimmed_sql, stmt_type);

    switch (stmt_type) {
        case StatementType::INSERT:
        case StatementType::UPDATE:
        case StatementType::DELETE:
        case StatementType::CREATE_TABLE:
        case StatementType::ALTER_TABLE:
        case StatementType::DROP_TABLE:
        case StatementType::TRUNCATE:
            parsed.is_write = true;
            parsed.is_transaction = false;
            break;
        case StatementType::BEGIN:
        case StatementType::COMMIT:
        case StatementType::ROLLBACK:
            parsed.is_write = false;
            parsed.is_transaction = true;
            break;
        default:
            parsed.is_write = false;
            parsed.is_transaction = false;
            break;
    }

    auto statement_info = std::make_shared<StatementInfo>(fingerprint, std::move(parsed));

    // Cache successful parse
    if (cache_) {
        cache_->put(statement_info);
    }

    return ParseResult::ok(statement_info);
}

StatementType MysqlSqlParser::detect_statement_type(std::string_view sql) {
    // Find first keyword (skip leading whitespace)
    size_t start = 0;
    while (start < sql.size() && std::isspace(static_cast<unsigned char>(sql[start]))) {
        ++start;
    }

    // Extract first word
    size_t end = start;
    while (end < sql.size() && std::isalpha(static_cast<unsigned char>(sql[end]))) {
        ++end;
    }

    if (start == end) {
        return StatementType::UNKNOWN;
    }

    std::string keyword(sql.substr(start, end - start));
    std::transform(keyword.begin(), keyword.end(), keyword.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    auto it = MYSQL_STMT_KEYWORDS.find(keyword);
    if (it == MYSQL_STMT_KEYWORDS.end()) {
        return StatementType::UNKNOWN;
    }

    // Refine CREATE/ALTER/DROP based on second keyword
    if (keyword == "create" || keyword == "drop") {
        size_t next_start = end;
        while (next_start < sql.size() && std::isspace(static_cast<unsigned char>(sql[next_start]))) {
            ++next_start;
        }
        size_t next_end = next_start;
        while (next_end < sql.size() && std::isalpha(static_cast<unsigned char>(sql[next_end]))) {
            ++next_end;
        }

        if (next_start < next_end) {
            std::string second(sql.substr(next_start, next_end - next_start));
            std::transform(second.begin(), second.end(), second.begin(),
                           [](unsigned char c) { return std::tolower(c); });

            if (second == "index" || second == "unique") {
                return keyword == "create" ? StatementType::CREATE_INDEX : StatementType::DROP_INDEX;
            }
        }
    }

    return it->second;
}

std::vector<TableRef> MysqlSqlParser::extract_tables(std::string_view sql, StatementType type) {
    std::vector<TableRef> tables;
    std::string sql_str(sql);

    // MySQL identifier: optional backtick-quoted or plain word
    // Pattern: optional `db`.`table` or db.table or just table
    static const std::regex TABLE_RE(
        R"((?:`([^`]+)`|(\w+))\.(?:`([^`]+)`|(\w+))|(?:`([^`]+)`|(\w+)))",
        std::regex::icase);

    auto extract_from_clause = [&](const std::string& clause) {
        auto begin = std::sregex_iterator(clause.begin(), clause.end(), TABLE_RE);
        auto end_it = std::sregex_iterator();

        for (auto it = begin; it != end_it; ++it) {
            const auto& match = *it;
            std::string schema, table;

            // Check for schema.table form
            if (match[1].matched || match[2].matched) {
                schema = match[1].matched ? match[1].str() : match[2].str();
                table = match[3].matched ? match[3].str() : match[4].str();
            } else {
                // Plain table name
                table = match[5].matched ? match[5].str() : match[6].str();
            }

            // Skip SQL keywords that might match
            std::string lower_table = table;
            std::transform(lower_table.begin(), lower_table.end(), lower_table.begin(),
                           [](unsigned char c) { return std::tolower(c); });

            static const std::unordered_set<std::string> SKIP_WORDS = {
                "select", "from", "where", "join", "inner", "left", "right",
                "outer", "cross", "on", "and", "or", "not", "in", "as",
                "set", "values", "into", "table", "index", "create", "drop",
                "alter", "insert", "update", "delete", "order", "by", "group",
                "having", "limit", "offset", "union", "all", "distinct",
                "between", "like", "is", "null", "true", "false", "exists",
                "case", "when", "then", "else", "end", "asc", "desc",
                "primary", "key", "foreign", "references", "constraint",
                "default", "auto_increment", "if", "temporary", "cascade",
            };

            if (SKIP_WORDS.count(lower_table) > 0) {
                continue;
            }

            TableRef ref;
            ref.schema = std::move(schema);
            ref.table = std::move(table);
            tables.push_back(std::move(ref));
        }
    };

    // Strategy varies by statement type
    switch (type) {
        case StatementType::SELECT: {
            // Extract FROM clause
            static const std::regex FROM_RE(
                R"(\bFROM\s+(.+?)(?:\bWHERE\b|\bGROUP\b|\bORDER\b|\bLIMIT\b|\bUNION\b|\bHAVING\b|$))",
                std::regex::icase);
            std::smatch from_match;
            if (std::regex_search(sql_str, from_match, FROM_RE)) {
                extract_from_clause(from_match[1].str());
            }
            // Extract JOIN tables
            static const std::regex JOIN_RE(
                R"(\bJOIN\s+(?:`([^`]+)`|(\w+))(?:\.(?:`([^`]+)`|(\w+)))?)",
                std::regex::icase);
            auto jbegin = std::sregex_iterator(sql_str.begin(), sql_str.end(), JOIN_RE);
            auto jend = std::sregex_iterator();
            for (auto it = jbegin; it != jend; ++it) {
                const auto& m = *it;
                std::string t = m[1].matched ? m[1].str() : m[2].str();
                if (!t.empty()) {
                    TableRef ref;
                    ref.table = std::move(t);
                    tables.push_back(std::move(ref));
                }
            }
            break;
        }

        case StatementType::INSERT: {
            static const std::regex INSERT_RE(
                R"(\bINTO\s+(?:`([^`]+)`|(\w+))(?:\.(?:`([^`]+)`|(\w+)))?)",
                std::regex::icase);
            std::smatch m;
            if (std::regex_search(sql_str, m, INSERT_RE)) {
                TableRef ref;
                if (m[3].matched || m[4].matched) {
                    ref.schema = m[1].matched ? m[1].str() : m[2].str();
                    ref.table = m[3].matched ? m[3].str() : m[4].str();
                } else {
                    ref.table = m[1].matched ? m[1].str() : m[2].str();
                }
                tables.push_back(std::move(ref));
            }
            break;
        }

        case StatementType::UPDATE: {
            static const std::regex UPDATE_RE(
                R"(\bUPDATE\s+(?:`([^`]+)`|(\w+))(?:\.(?:`([^`]+)`|(\w+)))?)",
                std::regex::icase);
            std::smatch m;
            if (std::regex_search(sql_str, m, UPDATE_RE)) {
                TableRef ref;
                if (m[3].matched || m[4].matched) {
                    ref.schema = m[1].matched ? m[1].str() : m[2].str();
                    ref.table = m[3].matched ? m[3].str() : m[4].str();
                } else {
                    ref.table = m[1].matched ? m[1].str() : m[2].str();
                }
                tables.push_back(std::move(ref));
            }
            break;
        }

        case StatementType::DELETE: {
            static const std::regex DELETE_RE(
                R"(\bFROM\s+(?:`([^`]+)`|(\w+))(?:\.(?:`([^`]+)`|(\w+)))?)",
                std::regex::icase);
            std::smatch m;
            if (std::regex_search(sql_str, m, DELETE_RE)) {
                TableRef ref;
                if (m[3].matched || m[4].matched) {
                    ref.schema = m[1].matched ? m[1].str() : m[2].str();
                    ref.table = m[3].matched ? m[3].str() : m[4].str();
                } else {
                    ref.table = m[1].matched ? m[1].str() : m[2].str();
                }
                tables.push_back(std::move(ref));
            }
            break;
        }

        case StatementType::CREATE_TABLE:
        case StatementType::ALTER_TABLE:
        case StatementType::DROP_TABLE:
        case StatementType::TRUNCATE: {
            static const std::regex DDL_RE(
                R"(\bTABLE\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?(?:`([^`]+)`|(\w+))(?:\.(?:`([^`]+)`|(\w+)))?)",
                std::regex::icase);
            std::smatch m;
            if (std::regex_search(sql_str, m, DDL_RE)) {
                TableRef ref;
                if (m[3].matched || m[4].matched) {
                    ref.schema = m[1].matched ? m[1].str() : m[2].str();
                    ref.table = m[3].matched ? m[3].str() : m[4].str();
                } else {
                    ref.table = m[1].matched ? m[1].str() : m[2].str();
                }
                tables.push_back(std::move(ref));
            }
            break;
        }

        default:
            break;
    }

    return tables;
}

} // namespace sqlproxy
