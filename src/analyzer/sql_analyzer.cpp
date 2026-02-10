#include "analyzer/sql_analyzer.hpp"
#include "parser/ast_keys.hpp"

// libpg_query C API
extern "C" {
#include "pg_query.h"
}

#include "core/json.hpp"

#include <algorithm>
#include <cctype>
#include <future>
#include <unordered_set>

using json = sqlproxy::JsonValue;

namespace sqlproxy {

// ============================================================================
// Constexpr AST node keys (libpg_query JSON field names used 2+ times)
// ============================================================================

// Statement types
static constexpr std::string_view kSelectStmt    = "SelectStmt";
static constexpr std::string_view kInsertStmt    = "InsertStmt";
static constexpr std::string_view kUpdateStmt    = "UpdateStmt";
static constexpr std::string_view kDeleteStmt    = "DeleteStmt";

// Node types
static constexpr std::string_view kJoinExpr      = "JoinExpr";
static constexpr std::string_view kSubLink       = "SubLink";
static constexpr std::string_view kFuncCall      = "FuncCall";
static constexpr std::string_view kResTarget     = "ResTarget";
static constexpr std::string_view kColumnRef     = "ColumnRef";
static constexpr std::string_view kStringNode    = "String";
static constexpr std::string_view kIntegerNode   = "Integer";
static constexpr std::string_view kCaseExpr      = "CaseExpr";
static constexpr std::string_view kCaseWhen      = "CaseWhen";
static constexpr std::string_view kCoalesceExpr  = "CoalesceExpr";
static constexpr std::string_view kTypeCast      = "TypeCast";
static constexpr std::string_view kBoolExpr      = "BoolExpr";
static constexpr std::string_view kNullTest      = "NullTest";
static constexpr std::string_view kAExpr         = "A_Expr";
static constexpr std::string_view kAConst        = "A_Const";
static constexpr std::string_view kAArrayExpr    = "A_ArrayExpr";
static constexpr std::string_view kAStar         = "A_Star";
static constexpr std::string_view kRangeSubselect = "RangeSubselect";
static constexpr std::string_view kWithClause    = "WithClause";
static constexpr std::string_view kCommonTableExpr = "CommonTableExpr";

// Field names
static constexpr std::string_view kArgs          = "args";
static constexpr std::string_view kArg           = "arg";
static constexpr std::string_view kFields        = "fields";
static constexpr std::string_view kFromClause    = "fromClause";
static constexpr std::string_view kWhereClause   = "whereClause";
static constexpr std::string_view kTargetList    = "targetList";
static constexpr std::string_view kRelation      = "relation";
static constexpr std::string_view kSelectStmtFld = "selectStmt";
static constexpr std::string_view kSubselect     = "subselect";
static constexpr std::string_view kSubquery      = "subquery";
static constexpr std::string_view kTestexpr      = "testexpr";
static constexpr std::string_view kLarg          = "larg";
static constexpr std::string_view kRarg          = "rarg";
static constexpr std::string_view kLexpr         = "lexpr";
static constexpr std::string_view kRexpr         = "rexpr";
static constexpr std::string_view kFuncname      = "funcname";
static constexpr std::string_view kAggStar       = "agg_star";
static constexpr std::string_view kCols          = "cols";
static constexpr std::string_view kVal           = "val";
static constexpr std::string_view kIval          = "ival";
static constexpr std::string_view kFval          = "fval";
static constexpr std::string_view kStmts         = "stmts";
static constexpr std::string_view kStmt          = "stmt";
static constexpr std::string_view kQuals         = "quals";
static constexpr std::string_view kCtes          = "ctes";
static constexpr std::string_view kCtequery      = "ctequery";
static constexpr std::string_view kWithClauseFld = "withClause";
static constexpr std::string_view kGroupClause   = "groupClause";
static constexpr std::string_view kHavingClause  = "havingClause";
static constexpr std::string_view kLimitCount    = "limitCount";
static constexpr std::string_view kElements      = "elements";
static constexpr std::string_view kDefresult     = "defresult";
static constexpr std::string_view kExpr          = "expr";
static constexpr std::string_view kResult        = "result";
static constexpr std::string_view kName          = "name";
static constexpr char kDot = '.';
static constexpr std::string_view kDotPrefix     = ".";

// Projection expression type labels (used as both expression and fallback name)
static constexpr std::string_view kExprExpression    = "expression";
static constexpr std::string_view kExprSubquery      = "subquery";
static constexpr std::string_view kExprCase          = "case";
static constexpr std::string_view kExprTypecast      = "typecast";
static constexpr std::string_view kExprCoalesce      = "coalesce";
static constexpr std::string_view kExprUnknown       = "unknown";
static constexpr std::string_view kExprIntLiteral    = "integer_literal";
static constexpr std::string_view kExprStrLiteral    = "string_literal";
static constexpr std::string_view kExprFloatLiteral  = "float_literal";
static constexpr std::string_view kExprLiteral       = "literal";

// ============================================================================
// Static lookup tables
// ============================================================================

static const std::unordered_set<std::string> AGGREGATE_FUNCTIONS = {
    "count", "sum", "avg", "max", "min",
    "array_agg", "string_agg", "bool_and", "bool_or",
    "bit_and", "bit_or", "every", "json_agg", "jsonb_agg",
    "json_object_agg", "jsonb_object_agg", "xmlagg",
    "percentile_cont", "percentile_disc", "mode",
    "rank", "dense_rank", "row_number", "ntile",
    "lag", "lead", "first_value", "last_value", "nth_value",
    "cume_dist", "percent_rank",
    "corr", "covar_pop", "covar_samp",
    "regr_avgx", "regr_avgy", "regr_count",
    "regr_intercept", "regr_r2", "regr_slope",
    "regr_sxx", "regr_sxy", "regr_syy",
    "stddev", "stddev_pop", "stddev_samp",
    "variance", "var_pop", "var_samp"
};

// ============================================================================
// JSON helper: safe access with default
// ============================================================================

// Safely check if a JSON object contains a key and it is not null
[[nodiscard]] static inline bool has_key(const json& node, std::string_view key) {
    return node.is_object() && node.contains(key) && !node[key].is_null();
}

// Safely get a string value from a JSON node, returning empty string on failure
[[nodiscard]] static inline std::string get_string(const json& node, std::string_view key) {
    if (node.is_object() && node.contains(key) && node[key].is_string()) {
        return node[key].get<std::string>();
    }
    return {};
}

// Safely get an integer value from a JSON node
[[nodiscard]] static inline std::optional<int64_t> get_int(const json& node, std::string_view key) {
    if (node.is_object() && node.contains(key) && node[key].is_number_integer()) {
        return node[key].get<int64_t>();
    }
    return std::nullopt;
}

// ============================================================================
// Parse JSON from PgQueryParseResult
// ============================================================================

[[nodiscard]] static json parse_json_tree(void* parse_tree) {
    if (!parse_tree) {
        return json();
    }

    auto* parse_result = static_cast<PgQueryParseResult*>(parse_tree);
    if (!parse_result->parse_tree) {
        return json();
    }

    try {
        return json::parse(parse_result->parse_tree);
    } catch (const json::parse_error&) {
        return json();
    }
}

// Get the first statement node from the top-level parse tree
// Structure: {"version": N, "stmts": [{"stmt": {"SelectStmt": {...}}}]}
[[nodiscard]] static json get_first_stmt(const json& root) {
    if (!has_key(root, kStmts) || !root[kStmts].is_array() || root[kStmts].empty()) {
        return json();
    }

    const auto& first = root[kStmts][0];
    if (!has_key(first, kStmt)) {
        return json();
    }

    return first[kStmt];
}

// Get the inner statement object (e.g., the SelectStmt, InsertStmt, etc.)
// Returns a pair of (statement_type_name, statement_body)
[[nodiscard]] static std::pair<std::string, json> get_stmt_body(const json& stmt) {
    if (!stmt.is_object()) {
        return {"", json()};
    }

    for (auto it = stmt.begin(); it != stmt.end(); ++it) {
        if (it.value().is_object()) {
            return {it.key(), it.value()};
        }
    }

    return {"", json()};
}

// ============================================================================
// Recursive column reference extraction from any expression node
// ============================================================================

// Extract all column names from a ColumnRef node
// ColumnRef: {"fields": [{"String": {"sval": "table"}}, {"String": {"sval": "col"}}]}
// or: {"fields": [{"String": {"sval": "col"}}]}
// or: {"fields": [{"A_Star": {}}]} for SELECT *
static void extract_column_refs_from_node(const json& node,
                                          std::vector<std::string>& columns,
                                          std::vector<std::string>& table_qualified_columns);

static void walk_expr_for_columns(const json& node,
                                  std::vector<std::string>& columns,
                                  std::vector<std::string>& table_qualified_columns) {
    if (!node.is_object() && !node.is_array()) {
        return;
    }

    if (node.is_array()) {
        for (const auto& elem : node) {
            walk_expr_for_columns(elem, columns, table_qualified_columns);
        }
        return;
    }

    // Object: check for known expression node types
    if (has_key(node, kColumnRef)) {
        extract_column_refs_from_node(node[kColumnRef], columns, table_qualified_columns);
        return;
    }

    // A_Expr: arithmetic/comparison expression
    if (has_key(node, kAExpr)) {
        const auto& expr = node[kAExpr];
        if (has_key(expr, kLexpr)) {
            walk_expr_for_columns(expr[kLexpr], columns, table_qualified_columns);
        }
        if (has_key(expr, kRexpr)) {
            walk_expr_for_columns(expr[kRexpr], columns, table_qualified_columns);
        }
        return;
    }

    // BoolExpr: AND/OR/NOT
    if (has_key(node, kBoolExpr)) {
        const auto& expr = node[kBoolExpr];
        if (has_key(expr, kArgs) && expr[kArgs].is_array()) {
            for (const auto& arg : expr[kArgs]) {
                walk_expr_for_columns(arg, columns, table_qualified_columns);
            }
        }
        return;
    }

    // FuncCall
    if (has_key(node, kFuncCall)) {
        const auto& func = node[kFuncCall];
        if (has_key(func, kArgs) && func[kArgs].is_array()) {
            for (const auto& arg : func[kArgs]) {
                walk_expr_for_columns(arg, columns, table_qualified_columns);
            }
        }
        return;
    }

    // NullTest (e.g., col IS NULL)
    if (has_key(node, kNullTest)) {
        const auto& nt = node[kNullTest];
        if (has_key(nt, kArg)) {
            walk_expr_for_columns(nt[kArg], columns, table_qualified_columns);
        }
        return;
    }

    // SubLink (subquery expression)
    if (has_key(node, kSubLink)) {
        const auto& sub = node[kSubLink];
        if (has_key(sub, kTestexpr)) {
            walk_expr_for_columns(sub[kTestexpr], columns, table_qualified_columns);
        }
        // Don't recurse into the subselect - those are separate scopes
        return;
    }

    // TypeCast (e.g., col::text)
    if (has_key(node, kTypeCast)) {
        const auto& tc = node[kTypeCast];
        if (has_key(tc, kArg)) {
            walk_expr_for_columns(tc[kArg], columns, table_qualified_columns);
        }
        return;
    }

    // CaseExpr
    if (has_key(node, kCaseExpr)) {
        const auto& ce = node[kCaseExpr];
        if (has_key(ce, kArg)) {
            walk_expr_for_columns(ce[kArg], columns, table_qualified_columns);
        }
        if (has_key(ce, kArgs) && ce[kArgs].is_array()) {
            for (const auto& when_clause : ce[kArgs]) {
                if (has_key(when_clause, kCaseWhen)) {
                    const auto& cw = when_clause[kCaseWhen];
                    if (has_key(cw, kExpr)) {
                        walk_expr_for_columns(cw[kExpr], columns, table_qualified_columns);
                    }
                    if (has_key(cw, kResult)) {
                        walk_expr_for_columns(cw[kResult], columns, table_qualified_columns);
                    }
                }
            }
        }
        if (has_key(ce, kDefresult)) {
            walk_expr_for_columns(ce[kDefresult], columns, table_qualified_columns);
        }
        return;
    }

    // CoalesceExpr
    if (has_key(node, kCoalesceExpr)) {
        const auto& ce = node[kCoalesceExpr];
        if (has_key(ce, kArgs) && ce[kArgs].is_array()) {
            for (const auto& arg : ce[kArgs]) {
                walk_expr_for_columns(arg, columns, table_qualified_columns);
            }
        }
        return;
    }

    // A_ArrayExpr (array constructor)
    if (has_key(node, kAArrayExpr)) {
        const auto& arr = node[kAArrayExpr];
        if (has_key(arr, kElements) && arr[kElements].is_array()) {
            for (const auto& elem : arr[kElements]) {
                walk_expr_for_columns(elem, columns, table_qualified_columns);
            }
        }
        return;
    }

    // For any other object, recurse into its values (catch-all for unknown node types)
    for (auto it = node.begin(); it != node.end(); ++it) {
        if (it.value().is_object() || it.value().is_array()) {
            walk_expr_for_columns(it.value(), columns, table_qualified_columns);
        }
    }
}

static void extract_column_refs_from_node(const json& col_ref,
                                          std::vector<std::string>& columns,
                                          std::vector<std::string>& table_qualified_columns) {
    if (!has_key(col_ref, kFields) || !col_ref[kFields].is_array()) {
        return;
    }

    const auto& fields = col_ref[kFields];
    std::vector<std::string> parts;

    for (const auto& field : fields) {
        if (has_key(field, kStringNode)) {
            // libpg_query v17 uses "sval" inside String node
            std::string val = get_string(field[kStringNode], ast::kSval);
            if (val.empty()) {
                // Fallback: some versions use "str"
                val = get_string(field[kStringNode], ast::kStr);
            }
            if (!val.empty()) {
                parts.emplace_back(std::move(val));
            }
        }
        // A_Star is handled separately (SELECT *)
    }

    if (parts.empty()) {
        return;
    }

    // Last part is the column name, preceding parts are table/schema qualifiers
    const std::string& col_name = parts.back();
    columns.push_back(col_name);

    if (parts.size() >= 2) {
        // table.column or schema.table.column
        std::string qualified = parts[parts.size() - 2] + std::string(kDotPrefix) + col_name;
        table_qualified_columns.emplace_back(std::move(qualified));
    }
}

// Simplified version: just extract column names (no table qualification tracking)
static void collect_column_names(const json& node, std::vector<std::string>& columns) {
    std::vector<std::string> dummy;
    walk_expr_for_columns(node, columns, dummy);
}

// ============================================================================
// Check if a ColumnRef is a star expansion (SELECT *)
// ============================================================================

[[nodiscard]] static bool is_star_ref(const json& col_ref) {
    if (!has_key(col_ref, kFields) || !col_ref[kFields].is_array()) {
        return false;
    }

    for (const auto& field : col_ref[kFields]) {
        if (has_key(field, kAStar)) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// Extract function name from FuncCall node
// ============================================================================

[[nodiscard]] static std::string extract_func_name(const json& func_call) {
    if (!has_key(func_call, kFuncname) || !func_call[kFuncname].is_array()) {
        return {};
    }

    // funcname is an array of String nodes (e.g., [{"String": {"sval": "upper"}}])
    // For schema-qualified: [{"String": {"sval": "pg_catalog"}}, {"String": {"sval": "count"}}]
    // We want the last element (actual function name)
    const auto& funcname = func_call[kFuncname];
    if (funcname.empty()) {
        return {};
    }

    const auto& last = funcname.back();
    if (has_key(last, kStringNode)) {
        std::string name = get_string(last[kStringNode], ast::kSval);
        if (name.empty()) {
            name = get_string(last[kStringNode], ast::kStr);
        }
        return name;
    }

    return {};
}

// ============================================================================
// Check if a function name is an aggregate
// ============================================================================

[[nodiscard]] static bool is_aggregate_function(const std::string& name) {
    // Convert to lowercase for case-insensitive comparison
    std::string lower;
    lower.reserve(name.size());
    for (const char c : name) {
        lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return AGGREGATE_FUNCTIONS.count(lower) > 0;
}

// ============================================================================
// Forward declarations for mutually recursive / order-dependent functions
// ============================================================================

static void walk_for_subquery_tables(const json& node,
                                     std::vector<TableRef>& tables,
                                     std::unordered_set<std::string>& seen);

static void extract_join_filter_columns(const json& node,
                                        std::vector<ColumnRef>& columns);

// ============================================================================
// Recursive AST walking for tables (RangeVar nodes)
// ============================================================================

static void walk_for_tables(const json& node,
                            std::vector<TableRef>& tables,
                            std::unordered_set<std::string>& seen) {
    if (node.is_array()) {
        for (const auto& elem : node) {
            walk_for_tables(elem, tables, seen);
        }
        return;
    }

    if (!node.is_object()) {
        return;
    }

    // RangeVar: direct table reference
    if (has_key(node, ast::kRangeVar)) {
        const auto& rv = node[ast::kRangeVar];
        std::string relname = get_string(rv, ast::kRelname);
        if (!relname.empty()) {
            std::string schemaname = get_string(rv, ast::kSchemaname);
            std::string alias_name;

            // Extract alias from Alias node
            if (has_key(rv, ast::kAliasFld) && has_key(rv[ast::kAliasFld], ast::kAlias)) {
                alias_name = get_string(rv[ast::kAliasFld][ast::kAlias], ast::kAliasname);
            } else if (has_key(rv, ast::kAliasFld) && rv[ast::kAliasFld].is_object()) {
                alias_name = get_string(rv[ast::kAliasFld], ast::kAliasname);
            }

            std::string key;
            key.reserve(schemaname.size() + 1 + relname.size());
            key = schemaname;
            key += kDot;
            key += relname;

            if (seen.insert(std::move(key)).second) {
                tables.emplace_back(std::move(schemaname), std::move(relname), std::move(alias_name));
            }
        }
        // Don't return - RangeVar won't have sub-nodes with more tables
        return;
    }

    // JoinExpr: walk left and right args, plus quals
    if (has_key(node, kJoinExpr)) {
        const auto& je = node[kJoinExpr];
        if (has_key(je, kLarg)) {
            walk_for_tables(je[kLarg], tables, seen);
        }
        if (has_key(je, kRarg)) {
            walk_for_tables(je[kRarg], tables, seen);
        }
        // Don't recurse into quals - those contain column refs, not table refs
        return;
    }

    // RangeSubselect: subquery in FROM clause - recurse into subselect
    if (has_key(node, kRangeSubselect)) {
        const auto& rs = node[kRangeSubselect];
        if (has_key(rs, kSubquery)) {
            walk_for_tables(rs[kSubquery], tables, seen);
        }
        return;
    }

    // For any SelectStmt (including CTEs), walk fromClause
    if (has_key(node, kSelectStmt)) {
        const auto& ss = node[kSelectStmt];
        if (has_key(ss, kFromClause)) {
            walk_for_tables(ss[kFromClause], tables, seen);
        }
        // Walk CTEs
        if (has_key(ss, kWithClauseFld)) {
            // withClause can be {"WithClause": {...}} or directly {...}
            const auto& wc_outer = ss[kWithClauseFld];
            const json& wc = has_key(wc_outer, kWithClause)
                             ? wc_outer[kWithClause] : wc_outer;
            if (has_key(wc, kCtes) && wc[kCtes].is_array()) {
                for (const auto& cte : wc[kCtes]) {
                    // CTE can be {"CommonTableExpr": {...}} or directly {...}
                    const json& cte_body = has_key(cte, kCommonTableExpr)
                                           ? cte[kCommonTableExpr] : cte;
                    if (has_key(cte_body, kCtequery)) {
                        walk_for_tables(cte_body[kCtequery], tables, seen);
                    }
                }
            }
        }
        // Walk subqueries in WHERE clause
        if (has_key(ss, kWhereClause)) {
            walk_for_subquery_tables(ss[kWhereClause], tables, seen);
        }
        return;
    }

    // InsertStmt: walk relation and selectStmt
    if (has_key(node, kInsertStmt)) {
        const auto& is = node[kInsertStmt];
        if (has_key(is, kRelation)) {
            const json wrapped = json::wrap(ast::kRangeVar, is[kRelation]);
            walk_for_tables(wrapped, tables, seen);
        }
        if (has_key(is, kSelectStmtFld)) {
            walk_for_tables(is[kSelectStmtFld], tables, seen);
        }
        return;
    }

    // UpdateStmt: walk relation and fromClause
    if (has_key(node, kUpdateStmt)) {
        const auto& us = node[kUpdateStmt];
        if (has_key(us, kRelation)) {
            const json wrapped = json::wrap(ast::kRangeVar, us[kRelation]);
            walk_for_tables(wrapped, tables, seen);
        }
        if (has_key(us, kFromClause)) {
            walk_for_tables(us[kFromClause], tables, seen);
        }
        if (has_key(us, kWhereClause)) {
            walk_for_subquery_tables(us[kWhereClause], tables, seen);
        }
        return;
    }

    // DeleteStmt: walk relation
    if (has_key(node, kDeleteStmt)) {
        const auto& ds = node[kDeleteStmt];
        if (has_key(ds, kRelation)) {
            const json wrapped = json::wrap(ast::kRangeVar, ds[kRelation]);
            walk_for_tables(wrapped, tables, seen);
        }
        if (has_key(ds, kWhereClause)) {
            walk_for_subquery_tables(ds[kWhereClause], tables, seen);
        }
        return;
    }

    // Generic: recurse into all values
    for (auto it = node.begin(); it != node.end(); ++it) {
        if (it.value().is_object() || it.value().is_array()) {
            walk_for_tables(it.value(), tables, seen);
        }
    }
}

// Walk expression trees for SubLink/RangeSubselect nodes containing table refs
static void walk_for_subquery_tables(const json& node,
                                     std::vector<TableRef>& tables,
                                     std::unordered_set<std::string>& seen) {
    if (node.is_array()) {
        for (const auto& elem : node) {
            walk_for_subquery_tables(elem, tables, seen);
        }
        return;
    }

    if (!node.is_object()) {
        return;
    }

    if (has_key(node, kSubLink)) {
        const auto& sub = node[kSubLink];
        if (has_key(sub, kSubselect)) {
            walk_for_tables(sub[kSubselect], tables, seen);
        }
        if (has_key(sub, kTestexpr)) {
            walk_for_subquery_tables(sub[kTestexpr], tables, seen);
        }
        return;
    }

    // Recurse into child nodes
    for (auto it = node.begin(); it != node.end(); ++it) {
        if (it.value().is_object() || it.value().is_array()) {
            walk_for_subquery_tables(it.value(), tables, seen);
        }
    }
}

// ============================================================================
// Recursive detection: has_subquery
// ============================================================================

static bool walk_for_subquery(const json& node) {
    if (node.is_array()) {
        for (const auto& elem : node) {
            if (walk_for_subquery(elem)) {
                return true;
            }
        }
        return false;
    }

    if (!node.is_object()) {
        return false;
    }

    if (has_key(node, kSubLink) || has_key(node, kRangeSubselect)) {
        return true;
    }

    for (auto it = node.begin(); it != node.end(); ++it) {
        if (it.value().is_object() || it.value().is_array()) {
            if (walk_for_subquery(it.value())) {
                return true;
            }
        }
    }

    return false;
}

// ============================================================================
// Recursive detection: has_join
// ============================================================================

static bool walk_for_join(const json& node) {
    if (node.is_array()) {
        for (const auto& elem : node) {
            if (walk_for_join(elem)) {
                return true;
            }
        }
        return false;
    }

    if (!node.is_object()) {
        return false;
    }

    if (has_key(node, kJoinExpr)) {
        return true;
    }

    for (auto it = node.begin(); it != node.end(); ++it) {
        if (it.value().is_object() || it.value().is_array()) {
            if (walk_for_join(it.value())) {
                return true;
            }
        }
    }

    return false;
}

// ============================================================================
// Recursive detection: has_aggregation
// ============================================================================

static bool walk_for_aggregation(const json& node) {
    if (node.is_array()) {
        for (const auto& elem : node) {
            if (walk_for_aggregation(elem)) {
                return true;
            }
        }
        return false;
    }

    if (!node.is_object()) {
        return false;
    }

    // Check for FuncCall with aggregate function name
    if (has_key(node, kFuncCall)) {
        const auto& func = node[kFuncCall];
        const std::string name = extract_func_name(func);
        if (!name.empty() && is_aggregate_function(name)) {
            return true;
        }
        // Also check agg_star (e.g., COUNT(*))
        if (has_key(func, kAggStar) && func[kAggStar].is_boolean() && func[kAggStar].get<bool>()) {
            return true;
        }
    }

    // Check for groupClause or havingClause in a SelectStmt
    if (has_key(node, kSelectStmt)) {
        const auto& ss = node[kSelectStmt];
        if (has_key(ss, kGroupClause) || has_key(ss, kHavingClause)) {
            return true;
        }
    }

    for (auto it = node.begin(); it != node.end(); ++it) {
        if (it.value().is_object() || it.value().is_array()) {
            if (walk_for_aggregation(it.value())) {
                return true;
            }
        }
    }

    return false;
}

// ============================================================================
// SQLAnalyzer public API
// ============================================================================

AnalysisResult SQLAnalyzer::analyze(const ParsedQuery& parsed, void* parse_tree) {
    AnalysisResult result;

    result.statement_type = parsed.type;
    result.sub_type = statement_type_to_string(parsed.type);

    if (!parse_tree) {
        // No parse tree available - classify tables from ParsedQuery
        for (const auto& table : parsed.tables) {
            if (stmt_mask::test(parsed.type, stmt_mask::kDML) &&
                result.target_tables.empty()) {
                result.target_tables.push_back(table);
                result.table_usage[table.full_name()] = TableUsage::WRITE;
            } else {
                result.source_tables.push_back(table);
                result.table_usage[table.full_name()] = TableUsage::READ;
            }
        }
        result.alias_to_table = build_alias_map(parsed.tables);
        return result;
    }

    // Use tables from parser (already extracted via RangeVar nodes)
    const auto tables = parsed.tables;

    // Classify table usage based on statement type
    for (const auto& table : tables) {
        if (parsed.type == StatementType::SELECT) {
            result.source_tables.push_back(table);
            result.table_usage[table.full_name()] = TableUsage::READ;
        } else if (stmt_mask::test(parsed.type, stmt_mask::kDML)) {
            // For DML, first table is target, rest are sources (if INSERT...SELECT)
            if (result.target_tables.empty()) {
                result.target_tables.push_back(table);
                result.table_usage[table.full_name()] = TableUsage::WRITE;
            } else {
                result.source_tables.push_back(table);
                result.table_usage[table.full_name()] = TableUsage::READ;
            }
        } else if (stmt_mask::test(parsed.type, stmt_mask::kDDL)) {
            // DDL: tables are targets (structurally modified)
            result.target_tables.push_back(table);
            result.table_usage[table.full_name()] = TableUsage::WRITE;
        } else {
            // Unknown statement type: treat as read
            result.source_tables.push_back(table);
            result.table_usage[table.full_name()] = TableUsage::READ;
        }
    }

    // Build alias map
    result.alias_to_table = build_alias_map(tables);

    // Extract projections for SELECT
    if (parsed.type == StatementType::SELECT) {
        result.projections = extract_projections(parse_tree);
        result.is_star_select = std::any_of(
            result.projections.begin(),
            result.projections.end(),
            [](const ProjectionColumn& p) { return p.is_star_expansion; }
        );
    }

    // Extract write columns for DML
    if (parsed.is_write && parsed.type != StatementType::DELETE) {
        result.write_columns = extract_write_columns(parse_tree, parsed.type);
    }

    // Extract filter columns (WHERE clause)
    result.filter_columns = extract_filter_columns(parse_tree);

    // Detect query characteristics (parallel — all are independent read-only AST walks)
    auto f_subquery = std::async(std::launch::async, has_subquery, parse_tree);
    auto f_aggregation = std::async(std::launch::async, has_aggregation, parse_tree);
    auto f_limit = std::async(std::launch::async, extract_limit, parse_tree);

    result.has_join = has_join(parse_tree);  // Run one on current thread
    result.has_subquery = f_subquery.get();
    result.has_aggregation = f_aggregation.get();
    result.limit_value = f_limit.get();

    return result;
}

// ============================================================================
// extract_tables - Walk AST for all RangeVar nodes
// ============================================================================

std::vector<TableRef> SQLAnalyzer::extract_tables(void* parse_tree_ptr, StatementType /*type*/) {
    std::vector<TableRef> tables;

    const json root = parse_json_tree(parse_tree_ptr);
    if (root.is_null()) {
        return tables;
    }

    const json stmt = get_first_stmt(root);
    if (stmt.is_null()) {
        return tables;
    }

    std::unordered_set<std::string> seen;
    walk_for_tables(stmt, tables, seen);

    return tables;
}

// ============================================================================
// extract_projections - Walk SelectStmt.targetList for ResTarget nodes
// ============================================================================

std::vector<ProjectionColumn> SQLAnalyzer::extract_projections(void* parse_tree) {
    std::vector<ProjectionColumn> projections;

    const json root = parse_json_tree(parse_tree);
    if (root.is_null()) {
        return projections;
    }

    const json stmt = get_first_stmt(root);
    if (stmt.is_null()) {
        return projections;
    }

    const auto [stmt_type, body] = get_stmt_body(stmt);
    if (stmt_type != kSelectStmt || body.is_null()) {
        return projections;
    }

    if (!has_key(body, kTargetList) || !body[kTargetList].is_array()) {
        return projections;
    }

    for (const auto& target_item : body[kTargetList]) {
        if (!has_key(target_item, kResTarget)) {
            continue;
        }

        const auto& res_target = target_item[kResTarget];
        ProjectionColumn col;

        // Extract alias name if present
        col.name = get_string(res_target, kName);

        if (!has_key(res_target, kVal)) {
            // No value expression - skip
            if (!col.name.empty()) {
                projections.emplace_back(std::move(col));
            }
            continue;
        }

        const auto& val = res_target[kVal];

        // Case 1: Direct ColumnRef
        if (has_key(val, kColumnRef)) {
            const auto& col_ref = val[kColumnRef];

            // Check for SELECT *
            if (is_star_ref(col_ref)) {
                col.is_star_expansion = true;
                if (col.name.empty()) {
                    col.name = "*";
                }
                projections.emplace_back(std::move(col));
                continue;
            }

            // Extract column name from fields
            if (has_key(col_ref, kFields) && col_ref[kFields].is_array()) {
                const auto& fields = col_ref[kFields];
                std::vector<std::string> parts;

                for (const auto& field : fields) {
                    if (has_key(field, kStringNode)) {
                        std::string sval = get_string(field[kStringNode], ast::kSval);
                        if (sval.empty()) {
                            sval = get_string(field[kStringNode], ast::kStr);
                        }
                        if (!sval.empty()) {
                            parts.emplace_back(std::move(sval));
                        }
                    }
                }

                if (!parts.empty()) {
                    // Last part is column name
                    col.derived_from.push_back(parts.back());
                    if (col.name.empty()) {
                        col.name = parts.back();
                    }
                    // Build expression for qualified references (e.g., "t.col")
                    if (parts.size() >= 2) {
                        std::string expr;
                        for (size_t i = 0; i < parts.size(); ++i) {
                            if (i > 0) expr += kDot;
                            expr += parts[i];
                        }
                        col.expression = std::move(expr);
                    }
                }
            }

            col.confidence = 1.0; // Direct column reference
            projections.emplace_back(std::move(col));
            continue;
        }

        // Case 2: FuncCall (e.g., UPPER(email), COUNT(*))
        if (has_key(val, kFuncCall)) {
            const auto& func = val[kFuncCall];
            std::string func_name = extract_func_name(func);

            col.expression = func_name;

            // Check for agg_star (COUNT(*))
            if (has_key(func, kAggStar) && func[kAggStar].is_boolean() && func[kAggStar].get<bool>()) {
                if (col.name.empty()) {
                    col.name = func_name;
                }
                col.expression = func_name + "(*)";
                col.confidence = 1.0;
                projections.emplace_back(std::move(col));
                continue;
            }

            // Extract source columns from function arguments
            if (has_key(func, kArgs) && func[kArgs].is_array()) {
                for (const auto& arg : func[kArgs]) {
                    std::vector<std::string> arg_cols;
                    collect_column_names(arg, arg_cols);
                    for (auto& c : arg_cols) {
                        col.derived_from.emplace_back(std::move(c));
                    }
                }
            }

            if (col.name.empty()) {
                col.name = func_name;
            }

            col.confidence = 0.9; // High confidence for direct function call
            projections.emplace_back(std::move(col));
            continue;
        }

        // Case 3: A_Expr (arithmetic expression, e.g., price * quantity)
        if (has_key(val, kAExpr)) {
            std::vector<std::string> expr_cols;
            collect_column_names(val, expr_cols);
            for (auto& c : expr_cols) {
                col.derived_from.emplace_back(std::move(c));
            }
            col.expression = kExprExpression;
            col.confidence = 0.8;

            if (col.name.empty() && !col.derived_from.empty()) {
                col.name = col.derived_from.front();
            }

            projections.emplace_back(std::move(col));
            continue;
        }

        // Case 4: SubLink (scalar subquery in SELECT list)
        if (has_key(val, kSubLink)) {
            col.expression = kExprSubquery;
            col.confidence = 0.5;

            if (col.name.empty()) {
                col.name = kExprSubquery;
            }

            projections.emplace_back(std::move(col));
            continue;
        }

        // Case 5: CaseExpr
        if (has_key(val, kCaseExpr)) {
            std::vector<std::string> case_cols;
            collect_column_names(val, case_cols);
            for (auto& c : case_cols) {
                col.derived_from.emplace_back(std::move(c));
            }
            col.expression = kExprCase;
            col.confidence = 0.7;

            if (col.name.empty() && !col.derived_from.empty()) {
                col.name = col.derived_from.front();
            } else if (col.name.empty()) {
                col.name = kExprCase;
            }

            projections.emplace_back(std::move(col));
            continue;
        }

        // Case 6: TypeCast
        if (has_key(val, kTypeCast)) {
            std::vector<std::string> cast_cols;
            collect_column_names(val, cast_cols);
            for (auto& c : cast_cols) {
                col.derived_from.emplace_back(std::move(c));
            }
            col.expression = kExprTypecast;
            col.confidence = 0.95;

            if (col.name.empty() && !col.derived_from.empty()) {
                col.name = col.derived_from.front();
            }

            projections.emplace_back(std::move(col));
            continue;
        }

        // Case 7: A_Const (literal value, e.g., SELECT 1, SELECT 'hello')
        if (has_key(val, kAConst)) {
            const auto& a_const = val[kAConst];
            if (has_key(a_const, kIval)) {
                col.expression = kExprIntLiteral;
            } else if (has_key(a_const, ast::kSval)) {
                col.expression = kExprStrLiteral;
            } else if (has_key(a_const, kFval)) {
                col.expression = kExprFloatLiteral;
            } else {
                col.expression = kExprLiteral;
            }
            col.confidence = 1.0;

            if (col.name.empty()) {
                col.name = col.expression;
            }

            projections.emplace_back(std::move(col));
            continue;
        }

        // Case 8: CoalesceExpr
        if (has_key(val, kCoalesceExpr)) {
            std::vector<std::string> coalesce_cols;
            collect_column_names(val, coalesce_cols);
            for (auto& c : coalesce_cols) {
                col.derived_from.emplace_back(std::move(c));
            }
            col.expression = kExprCoalesce;
            col.confidence = 0.85;

            if (col.name.empty() && !col.derived_from.empty()) {
                col.name = col.derived_from.front();
            } else if (col.name.empty()) {
                col.name = kExprCoalesce;
            }

            projections.emplace_back(std::move(col));
            continue;
        }

        // Fallback: try to extract any column references from the value expression
        {
            std::vector<std::string> fallback_cols;
            collect_column_names(val, fallback_cols);
            for (auto& c : fallback_cols) {
                col.derived_from.emplace_back(std::move(c));
            }
            col.expression = kExprUnknown;
            col.confidence = 0.5;

            if (col.name.empty() && !col.derived_from.empty()) {
                col.name = col.derived_from.front();
            } else if (col.name.empty()) {
                col.name = kExprUnknown;
            }

            projections.emplace_back(std::move(col));
        }
    }

    return projections;
}

// ============================================================================
// extract_filter_columns - Walk WHERE clause and JOIN ON conditions
// ============================================================================

std::vector<ColumnRef> SQLAnalyzer::extract_filter_columns(void* parse_tree) {
    std::vector<ColumnRef> columns;

    const json root = parse_json_tree(parse_tree);
    if (root.is_null()) {
        return columns;
    }

    const json stmt = get_first_stmt(root);
    if (stmt.is_null()) {
        return columns;
    }

    const auto [stmt_type, body] = get_stmt_body(stmt);
    if (body.is_null()) {
        return columns;
    }

    // Extract columns from WHERE clause
    if (has_key(body, kWhereClause)) {
        std::vector<std::string> col_names;
        std::vector<std::string> table_qualified;
        walk_expr_for_columns(body[kWhereClause], col_names, table_qualified);

        // Use table-qualified names when available, otherwise plain column names
        std::unordered_set<std::string> added;
        for (const auto& tq : table_qualified) {
            if (added.insert(tq).second) {
                size_t dot = tq.find(kDot);
                columns.emplace_back(std::string(tq.substr(0, dot)), std::string(tq.substr(dot + 1)));
            }
        }
        for (const auto& cn : col_names) {
            // Only add if not already added as table-qualified
            bool already_qualified = false;
            for (const auto& tq : table_qualified) {
                size_t dot = tq.find(kDot);
                if (dot != std::string::npos && tq.substr(dot + 1) == cn) {
                    already_qualified = true;
                    break;
                }
            }
            if (!already_qualified) {
                std::string key = std::string(kDotPrefix) + cn;
                if (added.insert(std::move(key)).second) {
                    columns.emplace_back(std::string(cn));
                }
            }
        }
    }

    // Extract columns from JOIN ON conditions
    if (has_key(body, kFromClause) && body[kFromClause].is_array()) {
        for (const auto& from_item : body[kFromClause]) {
            extract_join_filter_columns(from_item, columns);
        }
    }

    return columns;
}

// Helper: recursively extract column refs from JoinExpr quals
static void extract_join_filter_columns(const json& node, std::vector<ColumnRef>& columns) {
    if (!node.is_object()) {
        return;
    }

    if (has_key(node, kJoinExpr)) {
        const auto& je = node[kJoinExpr];

        // Extract columns from ON condition (quals)
        if (has_key(je, kQuals)) {
            std::vector<std::string> col_names;
            std::vector<std::string> table_qualified;
            walk_expr_for_columns(je[kQuals], col_names, table_qualified);

            std::unordered_set<std::string> added;
            for (const auto& tq : table_qualified) {
                if (added.insert(tq).second) {
                    const size_t dot = tq.find(kDot);
                    columns.emplace_back(std::string(tq.substr(0, dot)), std::string(tq.substr(dot + 1)));
                }
            }
            for (const auto& cn : col_names) {
                bool already_qualified = false;
                for (const auto& tq : table_qualified) {
                    const size_t dot = tq.find(kDot);
                    if (dot != std::string::npos && tq.substr(dot + 1) == cn) {
                        already_qualified = true;
                        break;
                    }
                }
                if (!already_qualified) {
                    std::string key = std::string(kDotPrefix) + cn;
                    if (added.insert(key).second) {
                        columns.emplace_back(std::string(cn));
                    }
                }
            }
        }

        // Recurse into left and right args for nested joins
        if (has_key(je, kLarg)) {
            extract_join_filter_columns(je[kLarg], columns);
        }
        if (has_key(je, kRarg)) {
            extract_join_filter_columns(je[kRarg], columns);
        }
    }
}

// ============================================================================
// extract_write_columns - Walk INSERT/UPDATE column lists
// ============================================================================

std::vector<ColumnRef> SQLAnalyzer::extract_write_columns(void* parse_tree, StatementType type) {
    std::vector<ColumnRef> columns;

    const json root = parse_json_tree(parse_tree);
    if (root.is_null()) {
        return columns;
    }

    const json stmt = get_first_stmt(root);
    if (stmt.is_null()) {
        return columns;
    }

    if (type == StatementType::INSERT) {
        if (!has_key(stmt, kInsertStmt)) {
            return columns;
        }
        const auto& insert_stmt = stmt[kInsertStmt];

        // Extract column list from "cols" array
        if (has_key(insert_stmt, kCols) && insert_stmt[kCols].is_array()) {
            for (const auto& col_item : insert_stmt[kCols]) {
                if (!has_key(col_item, kResTarget)) {
                    continue;
                }
                const auto& res_target = col_item[kResTarget];
                std::string col_name = get_string(res_target, kName);
                if (!col_name.empty()) {
                    columns.emplace_back(std::move(col_name));
                }
            }
        }
    } else if (type == StatementType::UPDATE) {
        if (!has_key(stmt, kUpdateStmt)) {
            return columns;
        }
        const auto& update_stmt = stmt[kUpdateStmt];

        // Extract SET target columns from "targetList"
        if (has_key(update_stmt, kTargetList) && update_stmt[kTargetList].is_array()) {
            for (const auto& target_item : update_stmt[kTargetList]) {
                if (!has_key(target_item, kResTarget)) {
                    continue;
                }
                const auto& res_target = target_item[kResTarget];
                std::string col_name = get_string(res_target, kName);
                if (!col_name.empty()) {
                    columns.emplace_back(std::move(col_name));
                }
            }
        }
    }

    return columns;
}

// ============================================================================
// build_alias_map
// ============================================================================

std::unordered_map<std::string, std::string> SQLAnalyzer::build_alias_map(
    const std::vector<TableRef>& tables) {

    std::unordered_map<std::string, std::string> alias_map;

    for (const auto& table : tables) {
        if (!table.alias.empty()) {
            alias_map[table.alias] = table.table;
        }
    }

    return alias_map;
}

// ============================================================================
// resolve_column
// ============================================================================

std::string SQLAnalyzer::resolve_column(
    const std::string& col,
    const std::unordered_map<std::string, std::string>& aliases) {

    // Check if column has table prefix: "alias.column"
    const size_t dot_pos = col.find(kDot);
    if (dot_pos == std::string::npos) {
        return col; // No prefix
    }

    const std::string prefix = col.substr(0, dot_pos);
    const std::string col_name = col.substr(dot_pos + 1);

    // Resolve alias to table name
    const auto it = aliases.find(prefix);
    if (it != aliases.end()) {
        return it->second + std::string(kDotPrefix) + col_name;
    }

    return col; // Prefix is already table name
}

// ============================================================================
// has_aggregation - Detect aggregate functions in AST
// ============================================================================

bool SQLAnalyzer::has_aggregation(void* parse_tree) {
    const json root = parse_json_tree(parse_tree);
    if (root.is_null()) {
        return false;
    }

    const json stmt = get_first_stmt(root);
    if (stmt.is_null()) {
        return false;
    }

    return walk_for_aggregation(stmt);
}

// ============================================================================
// has_subquery - Detect SubLink/RangeSubselect nodes
// ============================================================================

bool SQLAnalyzer::has_subquery(void* parse_tree) {
    const json root = parse_json_tree(parse_tree);
    if (root.is_null()) {
        return false;
    }

    const json stmt = get_first_stmt(root);
    if (stmt.is_null()) {
        return false;
    }

    return walk_for_subquery(stmt);
}

// ============================================================================
// has_join - Detect JoinExpr nodes
// ============================================================================

bool SQLAnalyzer::has_join(void* parse_tree) {
    const json root = parse_json_tree(parse_tree);
    if (root.is_null()) {
        return false;
    }

    const json stmt = get_first_stmt(root);
    if (stmt.is_null()) {
        return false;
    }

    return walk_for_join(stmt);
}

// ============================================================================
// extract_limit - Get LIMIT value from SelectStmt
// ============================================================================

std::optional<int64_t> SQLAnalyzer::extract_limit(void* parse_tree) {
    const json root = parse_json_tree(parse_tree);
    if (root.is_null()) {
        return std::nullopt;
    }

    const json stmt = get_first_stmt(root);
    if (stmt.is_null()) {
        return std::nullopt;
    }

    const auto [stmt_type, body] = get_stmt_body(stmt);
    if (stmt_type != kSelectStmt || body.is_null()) {
        return std::nullopt;
    }

    if (!has_key(body, kLimitCount)) {
        return std::nullopt;
    }

    const auto& limit_node = body[kLimitCount];

    // Case 1: A_Const with Integer value (e.g., LIMIT 10)
    // libpg_query v17 format: {"A_Const": {"ival": {"ival": 10}}}
    // or older: {"A_Const": {"val": {"Integer": {"ival": 10}}}}
    // or direct: {"Integer": {"ival": 10}}
    if (has_key(limit_node, kAConst)) {
        const auto& a_const = limit_node[kAConst];

        // v17 format: ival is an object with ival inside
        if (has_key(a_const, kIval)) {
            const auto& ival_node = a_const[kIval];
            if (ival_node.is_object()) {
                auto val = get_int(ival_node, kIval);
                if (val.has_value()) {
                    return val;
                }
            }
            // Direct integer value
            if (ival_node.is_number_integer()) {
                return ival_node.get<int64_t>();
            }
        }

        // Older format: val -> Integer -> ival
        if (has_key(a_const, kVal)) {
            const auto& val = a_const[kVal];
            if (has_key(val, kIntegerNode)) {
                return get_int(val[kIntegerNode], kIval);
            }
        }
    }

    // Direct Integer node
    if (has_key(limit_node, kIntegerNode)) {
        return get_int(limit_node[kIntegerNode], kIval);
    }

    return std::nullopt;
}

} // namespace sqlproxy
