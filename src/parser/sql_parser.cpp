#include "parser/sql_parser.hpp"
#include "core/utils.hpp"

// libpg_query C API
extern "C" {
#include "pg_query.h"
}

#include <nlohmann/json.hpp>

#include <cctype>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

namespace sqlproxy {

// Static hash map for O(1) statement type lookup
static const std::unordered_map<std::string_view, StatementType> STATEMENT_TYPE_MAP = {
    {"SelectStmt", StatementType::SELECT},
    {"InsertStmt", StatementType::INSERT},
    {"UpdateStmt", StatementType::UPDATE},
    {"DeleteStmt", StatementType::DELETE},
    {"CreateStmt", StatementType::CREATE_TABLE},
    {"AlterTableStmt", StatementType::ALTER_TABLE},
    {"DropStmt", StatementType::DROP_TABLE},
    {"TruncateStmt", StatementType::TRUNCATE},
    {"IndexStmt", StatementType::CREATE_INDEX},
    {"TransactionStmt", StatementType::BEGIN},  // Special case, will be refined
    // Additional statement types
    {"VacuumStmt", StatementType::UNKNOWN},
    {"ExplainStmt", StatementType::UNKNOWN},
    {"CopyStmt", StatementType::UNKNOWN},
    {"GrantStmt", StatementType::UNKNOWN},
    {"GrantRoleStmt", StatementType::UNKNOWN},
    {"RevokeStmt", StatementType::UNKNOWN},
    {"CreateSchemaStmt", StatementType::UNKNOWN},
    {"ViewStmt", StatementType::UNKNOWN},
    {"CreatedbStmt", StatementType::UNKNOWN},
    {"DropdbStmt", StatementType::UNKNOWN},
    {"VariableSetStmt", StatementType::SET},
    {"VariableShowStmt", StatementType::SHOW},
};

SQLParser::SQLParser(std::shared_ptr<ParseCache> cache)
    : cache_(std::move(cache)) {}

SQLParser::ParseResult SQLParser::parse(std::string_view sql) {
    // Empty query check
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

    // Cache miss - parse with libpg_query
    auto result = parse_with_libpgquery(trimmed_sql, fingerprint);

    // Cache successful parse
    if (result.success && cache_ && result.statement_info) {
        cache_->put(result.statement_info);
    }

    return result;
}

SQLParser::ParseResult SQLParser::parse_with_libpgquery(
    std::string_view sql,
    const QueryFingerprint& fingerprint) {

    // Call libpg_query parser
    PgQueryParseResult parse_result = pg_query_parse(std::string(sql).c_str());

    // Early return: parse error
    if (parse_result.error) {
        std::string error_msg = parse_result.error->message
            ? parse_result.error->message
            : "Unknown parse error";
        pg_query_free_parse_result(parse_result);
        return ParseResult::error(ErrorCode::SYNTAX_ERROR, std::move(error_msg));
    }

    // Extract statement type
    StatementType stmt_type = extract_statement_type(&parse_result);

    // Early return: unsupported statement
    if (stmt_type == StatementType::UNKNOWN) {
        pg_query_free_parse_result(parse_result);
        return ParseResult::error(
            ErrorCode::UNSUPPORTED_STATEMENT,
            "Unsupported or unrecognized statement type"
        );
    }

    // Build ParsedQuery
    ParsedQuery parsed;
    parsed.type = stmt_type;
    parsed.tables = extract_tables(&parse_result);

    // Determine flags using switch for better branch prediction
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

    // Create StatementInfo
    auto statement_info = std::make_shared<StatementInfo>(fingerprint, std::move(parsed));

    // Free libpg_query result
    pg_query_free_parse_result(parse_result);

    return ParseResult::ok(statement_info);
}

StatementType SQLParser::extract_statement_type(void* parse_result_ptr) {
    PgQueryParseResult* parse_result = static_cast<PgQueryParseResult*>(parse_result_ptr);

    // Early return: no parse tree
    if (!parse_result->parse_tree) {
        return StatementType::UNKNOWN;
    }

    // Parse tree is a JSON string containing the AST
    // Structure: {"version": N, "stmts": [{"stmt": {"SelectStmt": {...}}}]}
    std::string_view tree(parse_result->parse_tree);

    // Early return: find "stmt": {
    size_t stmt_pos = tree.find("\"stmt\"");
    if (stmt_pos == std::string_view::npos) {
        return StatementType::UNKNOWN;
    }

    // Early return: find opening brace
    size_t brace_pos = tree.find('{', stmt_pos);
    if (brace_pos == std::string_view::npos) {
        return StatementType::UNKNOWN;
    }

    // Early return: find statement type key start
    size_t quote_start = tree.find('"', brace_pos + 1);
    if (quote_start == std::string_view::npos) {
        return StatementType::UNKNOWN;
    }

    // Early return: find statement type key end
    size_t quote_end = tree.find('"', quote_start + 1);
    if (quote_end == std::string_view::npos) {
        return StatementType::UNKNOWN;
    }

    std::string_view stmt_type_str = tree.substr(quote_start + 1, quote_end - quote_start - 1);

    // O(1) hash map lookup instead of O(n) string comparisons
    auto it = STATEMENT_TYPE_MAP.find(stmt_type_str);
    if (it == STATEMENT_TYPE_MAP.end()) {
        return StatementType::UNKNOWN;
    }

    StatementType type = it->second;

    // Special case: TransactionStmt requires checking kind field
    if (type == StatementType::BEGIN && stmt_type_str == "TransactionStmt") {
        size_t kind_pos = tree.find("\"kind\"", quote_end);
        if (kind_pos == std::string_view::npos) {
            return StatementType::BEGIN;  // Default
        }

        size_t colon_pos = tree.find(':', kind_pos);
        if (colon_pos == std::string_view::npos) {
            return StatementType::BEGIN;
        }

        // Skip whitespace
        size_t num_start = colon_pos + 1;
        while (num_start < tree.size() && std::isspace(tree[num_start])) {
            ++num_start;
        }

        // Early return: no digit found
        if (num_start >= tree.size() || !std::isdigit(tree[num_start])) {
            return StatementType::BEGIN;
        }

        // TRANS_STMT_BEGIN=0, TRANS_STMT_COMMIT=2, TRANS_STMT_ROLLBACK=3
        int kind = tree[num_start] - '0';
        switch (kind) {
            case 0: return StatementType::BEGIN;
            case 2: return StatementType::COMMIT;
            case 3: return StatementType::ROLLBACK;
            default: return StatementType::BEGIN;
        }
    }

    return type;
}

/**
 * @brief Recursively walk the JSON AST to find all RangeVar nodes.
 *
 * RangeVar nodes represent table references in PostgreSQL's AST.
 * They appear in FROM clauses, JOINs, INSERT INTO, UPDATE, DELETE FROM,
 * subqueries, and CTEs. Walking the entire tree guarantees we find them all,
 * regardless of nesting depth.
 *
 * @param node Current JSON node being visited
 * @param tables Output vector of extracted table references
 * @param seen_tables Set for O(1) duplicate detection (keyed on "schema.table")
 */
static void find_range_vars(const nlohmann::json& node,
                            std::vector<TableRef>& tables,
                            std::unordered_set<std::string>& seen_tables) {
    if (node.is_object()) {
        if (node.contains("RangeVar")) {
            const auto& range_var = node["RangeVar"];

            // relname is the required table name field
            if (!range_var.contains("relname") || !range_var["relname"].is_string()) {
                // Malformed RangeVar - skip but continue walking
            } else {
                std::string table_name = range_var["relname"].get<std::string>();

                // schemaname is optional
                std::string schema_name;
                if (range_var.contains("schemaname") && range_var["schemaname"].is_string()) {
                    schema_name = range_var["schemaname"].get<std::string>();
                }

                // alias is optional
                // libpg_query JSON wraps nodes by type: {"alias": {"Alias": {"aliasname": "..."}}}
                // Handle both wrapped and unwrapped forms for robustness
                std::string alias_name;
                if (range_var.contains("alias") && range_var["alias"].is_object()) {
                    const auto& alias_node = range_var["alias"];
                    if (alias_node.contains("Alias") && alias_node["Alias"].is_object()) {
                        // Wrapped form: {"alias": {"Alias": {"aliasname": "..."}}}
                        const auto& inner = alias_node["Alias"];
                        if (inner.contains("aliasname") && inner["aliasname"].is_string()) {
                            alias_name = inner["aliasname"].get<std::string>();
                        }
                    } else if (alias_node.contains("aliasname") && alias_node["aliasname"].is_string()) {
                        // Unwrapped form: {"alias": {"aliasname": "..."}}
                        alias_name = alias_node["aliasname"].get<std::string>();
                    }
                }

                // Build dedup key: "schema.table"
                std::string key;
                key.reserve(schema_name.size() + 1 + table_name.size());
                key = schema_name;
                key += '.';
                key += table_name;

                // O(1) duplicate check - insert returns {iterator, was_inserted}
                if (seen_tables.insert(key).second) {
                    TableRef ref;
                    ref.schema = std::move(schema_name);
                    ref.table = std::move(table_name);
                    ref.alias = std::move(alias_name);
                    tables.push_back(std::move(ref));
                }
            }
        }

        // Continue walking all child nodes (handles subqueries, CTEs, JOINs, etc.)
        for (const auto& [key, val] : node.items()) {
            find_range_vars(val, tables, seen_tables);
        }
    } else if (node.is_array()) {
        for (const auto& elem : node) {
            find_range_vars(elem, tables, seen_tables);
        }
    }
}

std::vector<TableRef> SQLParser::extract_tables(void* parse_result_ptr) {
    std::vector<TableRef> tables;
    const auto* parse_result = static_cast<const PgQueryParseResult*>(parse_result_ptr);

    // Early return: no parse tree
    if (!parse_result->parse_tree) {
        return tables;
    }

    // Parse the JSON AST from libpg_query
    nlohmann::json ast;
    try {
        ast = nlohmann::json::parse(parse_result->parse_tree);
    } catch (const nlohmann::json::parse_error&) {
        // Malformed JSON from libpg_query - should not happen, but fail gracefully
        return tables;
    }

    // O(1) duplicate detection using hash set (schema.table as key)
    std::unordered_set<std::string> seen_tables;

    // Recursively walk the AST to find all RangeVar nodes
    find_range_vars(ast, tables, seen_tables);

    return tables;
}

} // namespace sqlproxy
