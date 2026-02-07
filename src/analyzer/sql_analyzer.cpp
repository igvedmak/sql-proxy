#include "analyzer/sql_analyzer.hpp"

// libpg_query C API
extern "C" {
#include "pg_query.h"
}

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <unordered_set>

using json = nlohmann::json;

namespace sqlproxy {

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
[[nodiscard]] static inline bool has_key(const json& node, const std::string& key) {
    return node.is_object() && node.contains(key) && !node[key].is_null();
}

// Safely get a string value from a JSON node, returning empty string on failure
[[nodiscard]] static inline std::string get_string(const json& node, const std::string& key) {
    if (node.is_object() && node.contains(key) && node[key].is_string()) {
        return node[key].get<std::string>();
    }
    return {};
}

// Safely get an integer value from a JSON node
[[nodiscard]] static inline std::optional<int64_t> get_int(const json& node, const std::string& key) {
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
    if (!has_key(root, "stmts") || !root["stmts"].is_array() || root["stmts"].empty()) {
        return json();
    }

    const auto& first = root["stmts"][0];
    if (!has_key(first, "stmt")) {
        return json();
    }

    return first["stmt"];
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
    if (has_key(node, "ColumnRef")) {
        extract_column_refs_from_node(node["ColumnRef"], columns, table_qualified_columns);
        return;
    }

    // A_Expr: arithmetic/comparison expression
    if (has_key(node, "A_Expr")) {
        const auto& expr = node["A_Expr"];
        if (has_key(expr, "lexpr")) {
            walk_expr_for_columns(expr["lexpr"], columns, table_qualified_columns);
        }
        if (has_key(expr, "rexpr")) {
            walk_expr_for_columns(expr["rexpr"], columns, table_qualified_columns);
        }
        return;
    }

    // BoolExpr: AND/OR/NOT
    if (has_key(node, "BoolExpr")) {
        const auto& expr = node["BoolExpr"];
        if (has_key(expr, "args") && expr["args"].is_array()) {
            for (const auto& arg : expr["args"]) {
                walk_expr_for_columns(arg, columns, table_qualified_columns);
            }
        }
        return;
    }

    // FuncCall
    if (has_key(node, "FuncCall")) {
        const auto& func = node["FuncCall"];
        if (has_key(func, "args") && func["args"].is_array()) {
            for (const auto& arg : func["args"]) {
                walk_expr_for_columns(arg, columns, table_qualified_columns);
            }
        }
        return;
    }

    // NullTest (e.g., col IS NULL)
    if (has_key(node, "NullTest")) {
        const auto& nt = node["NullTest"];
        if (has_key(nt, "arg")) {
            walk_expr_for_columns(nt["arg"], columns, table_qualified_columns);
        }
        return;
    }

    // SubLink (subquery expression)
    if (has_key(node, "SubLink")) {
        const auto& sub = node["SubLink"];
        if (has_key(sub, "testexpr")) {
            walk_expr_for_columns(sub["testexpr"], columns, table_qualified_columns);
        }
        // Don't recurse into the subselect - those are separate scopes
        return;
    }

    // TypeCast (e.g., col::text)
    if (has_key(node, "TypeCast")) {
        const auto& tc = node["TypeCast"];
        if (has_key(tc, "arg")) {
            walk_expr_for_columns(tc["arg"], columns, table_qualified_columns);
        }
        return;
    }

    // CaseExpr
    if (has_key(node, "CaseExpr")) {
        const auto& ce = node["CaseExpr"];
        if (has_key(ce, "arg")) {
            walk_expr_for_columns(ce["arg"], columns, table_qualified_columns);
        }
        if (has_key(ce, "args") && ce["args"].is_array()) {
            for (const auto& when_clause : ce["args"]) {
                if (has_key(when_clause, "CaseWhen")) {
                    const auto& cw = when_clause["CaseWhen"];
                    if (has_key(cw, "expr")) {
                        walk_expr_for_columns(cw["expr"], columns, table_qualified_columns);
                    }
                    if (has_key(cw, "result")) {
                        walk_expr_for_columns(cw["result"], columns, table_qualified_columns);
                    }
                }
            }
        }
        if (has_key(ce, "defresult")) {
            walk_expr_for_columns(ce["defresult"], columns, table_qualified_columns);
        }
        return;
    }

    // CoalesceExpr
    if (has_key(node, "CoalesceExpr")) {
        const auto& ce = node["CoalesceExpr"];
        if (has_key(ce, "args") && ce["args"].is_array()) {
            for (const auto& arg : ce["args"]) {
                walk_expr_for_columns(arg, columns, table_qualified_columns);
            }
        }
        return;
    }

    // A_ArrayExpr (array constructor)
    if (has_key(node, "A_ArrayExpr")) {
        const auto& arr = node["A_ArrayExpr"];
        if (has_key(arr, "elements") && arr["elements"].is_array()) {
            for (const auto& elem : arr["elements"]) {
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
    if (!has_key(col_ref, "fields") || !col_ref["fields"].is_array()) {
        return;
    }

    const auto& fields = col_ref["fields"];
    std::vector<std::string> parts;

    for (const auto& field : fields) {
        if (has_key(field, "String")) {
            // libpg_query v17 uses "sval" inside String node
            std::string val = get_string(field["String"], "sval");
            if (val.empty()) {
                // Fallback: some versions use "str"
                val = get_string(field["String"], "str");
            }
            if (!val.empty()) {
                parts.push_back(std::move(val));
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
        std::string qualified = parts[parts.size() - 2] + "." + col_name;
        table_qualified_columns.push_back(std::move(qualified));
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
    if (!has_key(col_ref, "fields") || !col_ref["fields"].is_array()) {
        return false;
    }

    for (const auto& field : col_ref["fields"]) {
        if (has_key(field, "A_Star")) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// Extract function name from FuncCall node
// ============================================================================

[[nodiscard]] static std::string extract_func_name(const json& func_call) {
    if (!has_key(func_call, "funcname") || !func_call["funcname"].is_array()) {
        return {};
    }

    // funcname is an array of String nodes (e.g., [{"String": {"sval": "upper"}}])
    // For schema-qualified: [{"String": {"sval": "pg_catalog"}}, {"String": {"sval": "count"}}]
    // We want the last element (actual function name)
    const auto& funcname = func_call["funcname"];
    if (funcname.empty()) {
        return {};
    }

    const auto& last = funcname.back();
    if (has_key(last, "String")) {
        std::string name = get_string(last["String"], "sval");
        if (name.empty()) {
            name = get_string(last["String"], "str");
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
    for (char c : name) {
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
    if (has_key(node, "RangeVar")) {
        const auto& rv = node["RangeVar"];
        std::string relname = get_string(rv, "relname");
        if (!relname.empty()) {
            std::string schemaname = get_string(rv, "schemaname");
            std::string alias_name;

            // Extract alias from Alias node
            if (has_key(rv, "alias") && has_key(rv["alias"], "Alias")) {
                alias_name = get_string(rv["alias"]["Alias"], "aliasname");
            } else if (has_key(rv, "alias") && rv["alias"].is_object()) {
                alias_name = get_string(rv["alias"], "aliasname");
            }

            std::string key;
            key.reserve(schemaname.size() + 1 + relname.size());
            key = schemaname;
            key += '.';
            key += relname;

            if (seen.insert(key).second) {
                TableRef ref;
                ref.schema = std::move(schemaname);
                ref.table = std::move(relname);
                ref.alias = std::move(alias_name);
                tables.push_back(std::move(ref));
            }
        }
        // Don't return - RangeVar won't have sub-nodes with more tables
        return;
    }

    // JoinExpr: walk left and right args, plus quals
    if (has_key(node, "JoinExpr")) {
        const auto& je = node["JoinExpr"];
        if (has_key(je, "larg")) {
            walk_for_tables(je["larg"], tables, seen);
        }
        if (has_key(je, "rarg")) {
            walk_for_tables(je["rarg"], tables, seen);
        }
        // Don't recurse into quals - those contain column refs, not table refs
        return;
    }

    // RangeSubselect: subquery in FROM clause - recurse into subselect
    if (has_key(node, "RangeSubselect")) {
        const auto& rs = node["RangeSubselect"];
        if (has_key(rs, "subquery")) {
            walk_for_tables(rs["subquery"], tables, seen);
        }
        return;
    }

    // For any SelectStmt (including CTEs), walk fromClause
    if (has_key(node, "SelectStmt")) {
        const auto& ss = node["SelectStmt"];
        if (has_key(ss, "fromClause")) {
            walk_for_tables(ss["fromClause"], tables, seen);
        }
        // Walk CTEs
        if (has_key(ss, "withClause")) {
            // withClause can be {"WithClause": {...}} or directly {...}
            const auto& wc_outer = ss["withClause"];
            const json& wc = has_key(wc_outer, "WithClause")
                             ? wc_outer["WithClause"] : wc_outer;
            if (has_key(wc, "ctes") && wc["ctes"].is_array()) {
                for (const auto& cte : wc["ctes"]) {
                    // CTE can be {"CommonTableExpr": {...}} or directly {...}
                    const json& cte_body = has_key(cte, "CommonTableExpr")
                                           ? cte["CommonTableExpr"] : cte;
                    if (has_key(cte_body, "ctequery")) {
                        walk_for_tables(cte_body["ctequery"], tables, seen);
                    }
                }
            }
        }
        // Walk subqueries in WHERE clause
        if (has_key(ss, "whereClause")) {
            walk_for_subquery_tables(ss["whereClause"], tables, seen);
        }
        return;
    }

    // InsertStmt: walk relation and selectStmt
    if (has_key(node, "InsertStmt")) {
        const auto& is = node["InsertStmt"];
        if (has_key(is, "relation")) {
            json wrapped;
            wrapped["RangeVar"] = is["relation"];
            walk_for_tables(wrapped, tables, seen);
        }
        if (has_key(is, "selectStmt")) {
            walk_for_tables(is["selectStmt"], tables, seen);
        }
        return;
    }

    // UpdateStmt: walk relation and fromClause
    if (has_key(node, "UpdateStmt")) {
        const auto& us = node["UpdateStmt"];
        if (has_key(us, "relation")) {
            json wrapped;
            wrapped["RangeVar"] = us["relation"];
            walk_for_tables(wrapped, tables, seen);
        }
        if (has_key(us, "fromClause")) {
            walk_for_tables(us["fromClause"], tables, seen);
        }
        if (has_key(us, "whereClause")) {
            walk_for_subquery_tables(us["whereClause"], tables, seen);
        }
        return;
    }

    // DeleteStmt: walk relation
    if (has_key(node, "DeleteStmt")) {
        const auto& ds = node["DeleteStmt"];
        if (has_key(ds, "relation")) {
            json wrapped;
            wrapped["RangeVar"] = ds["relation"];
            walk_for_tables(wrapped, tables, seen);
        }
        if (has_key(ds, "whereClause")) {
            walk_for_subquery_tables(ds["whereClause"], tables, seen);
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

    if (has_key(node, "SubLink")) {
        const auto& sub = node["SubLink"];
        if (has_key(sub, "subselect")) {
            walk_for_tables(sub["subselect"], tables, seen);
        }
        if (has_key(sub, "testexpr")) {
            walk_for_subquery_tables(sub["testexpr"], tables, seen);
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

    if (has_key(node, "SubLink") || has_key(node, "RangeSubselect")) {
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

    if (has_key(node, "JoinExpr")) {
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
    if (has_key(node, "FuncCall")) {
        const auto& func = node["FuncCall"];
        std::string name = extract_func_name(func);
        if (!name.empty() && is_aggregate_function(name)) {
            return true;
        }
        // Also check agg_star (e.g., COUNT(*))
        if (has_key(func, "agg_star") && func["agg_star"].is_boolean() && func["agg_star"].get<bool>()) {
            return true;
        }
    }

    // Check for groupClause or havingClause in a SelectStmt
    if (has_key(node, "SelectStmt")) {
        const auto& ss = node["SelectStmt"];
        if (has_key(ss, "groupClause") || has_key(ss, "havingClause")) {
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
        // No parse tree available - return minimal analysis from ParsedQuery
        result.source_tables = parsed.tables;
        return result;
    }

    // Use tables from parser (already extracted via RangeVar nodes)
    auto tables = parsed.tables;

    // Classify table usage based on statement type
    for (const auto& table : tables) {
        if (parsed.type == StatementType::SELECT) {
            result.source_tables.push_back(table);
            result.table_usage[table.full_name()] = TableUsage::READ;
        } else if (parsed.type == StatementType::INSERT ||
                   parsed.type == StatementType::UPDATE ||
                   parsed.type == StatementType::DELETE) {
            // For DML, first table is target, rest are sources (if INSERT...SELECT)
            if (result.target_tables.empty()) {
                result.target_tables.push_back(table);
                result.table_usage[table.full_name()] = TableUsage::WRITE;
            } else {
                result.source_tables.push_back(table);
                result.table_usage[table.full_name()] = TableUsage::READ;
            }
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

    // Detect query characteristics
    result.has_join = has_join(parse_tree);
    result.has_subquery = has_subquery(parse_tree);
    result.has_aggregation = has_aggregation(parse_tree);
    result.limit_value = extract_limit(parse_tree);

    return result;
}

// ============================================================================
// extract_tables - Walk AST for all RangeVar nodes
// ============================================================================

std::vector<TableRef> SQLAnalyzer::extract_tables(void* parse_tree_ptr, StatementType /*type*/) {
    std::vector<TableRef> tables;

    json root = parse_json_tree(parse_tree_ptr);
    if (root.is_null()) {
        return tables;
    }

    json stmt = get_first_stmt(root);
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

    json root = parse_json_tree(parse_tree);
    if (root.is_null()) {
        return projections;
    }

    json stmt = get_first_stmt(root);
    if (stmt.is_null()) {
        return projections;
    }

    auto [stmt_type, body] = get_stmt_body(stmt);
    if (stmt_type != "SelectStmt" || body.is_null()) {
        return projections;
    }

    if (!has_key(body, "targetList") || !body["targetList"].is_array()) {
        return projections;
    }

    for (const auto& target_item : body["targetList"]) {
        if (!has_key(target_item, "ResTarget")) {
            continue;
        }

        const auto& res_target = target_item["ResTarget"];
        ProjectionColumn col;

        // Extract alias name if present
        col.name = get_string(res_target, "name");

        if (!has_key(res_target, "val")) {
            // No value expression - skip
            if (!col.name.empty()) {
                projections.push_back(std::move(col));
            }
            continue;
        }

        const auto& val = res_target["val"];

        // Case 1: Direct ColumnRef
        if (has_key(val, "ColumnRef")) {
            const auto& col_ref = val["ColumnRef"];

            // Check for SELECT *
            if (is_star_ref(col_ref)) {
                col.is_star_expansion = true;
                if (col.name.empty()) {
                    col.name = "*";
                }
                projections.push_back(std::move(col));
                continue;
            }

            // Extract column name from fields
            if (has_key(col_ref, "fields") && col_ref["fields"].is_array()) {
                const auto& fields = col_ref["fields"];
                std::vector<std::string> parts;

                for (const auto& field : fields) {
                    if (has_key(field, "String")) {
                        std::string sval = get_string(field["String"], "sval");
                        if (sval.empty()) {
                            sval = get_string(field["String"], "str");
                        }
                        if (!sval.empty()) {
                            parts.push_back(std::move(sval));
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
                            if (i > 0) expr += '.';
                            expr += parts[i];
                        }
                        col.expression = std::move(expr);
                    }
                }
            }

            col.confidence = 1.0; // Direct column reference
            projections.push_back(std::move(col));
            continue;
        }

        // Case 2: FuncCall (e.g., UPPER(email), COUNT(*))
        if (has_key(val, "FuncCall")) {
            const auto& func = val["FuncCall"];
            std::string func_name = extract_func_name(func);

            col.expression = func_name;

            // Check for agg_star (COUNT(*))
            if (has_key(func, "agg_star") && func["agg_star"].is_boolean() && func["agg_star"].get<bool>()) {
                if (col.name.empty()) {
                    col.name = func_name;
                }
                col.expression = func_name + "(*)";
                col.confidence = 1.0;
                projections.push_back(std::move(col));
                continue;
            }

            // Extract source columns from function arguments
            if (has_key(func, "args") && func["args"].is_array()) {
                for (const auto& arg : func["args"]) {
                    std::vector<std::string> arg_cols;
                    collect_column_names(arg, arg_cols);
                    for (auto& c : arg_cols) {
                        col.derived_from.push_back(std::move(c));
                    }
                }
            }

            if (col.name.empty()) {
                col.name = func_name;
            }

            col.confidence = 0.9; // High confidence for direct function call
            projections.push_back(std::move(col));
            continue;
        }

        // Case 3: A_Expr (arithmetic expression, e.g., price * quantity)
        if (has_key(val, "A_Expr")) {
            std::vector<std::string> expr_cols;
            collect_column_names(val, expr_cols);
            for (auto& c : expr_cols) {
                col.derived_from.push_back(std::move(c));
            }
            col.expression = "expression";
            col.confidence = 0.8;

            if (col.name.empty() && !col.derived_from.empty()) {
                col.name = col.derived_from.front();
            }

            projections.push_back(std::move(col));
            continue;
        }

        // Case 4: SubLink (scalar subquery in SELECT list)
        if (has_key(val, "SubLink")) {
            col.expression = "subquery";
            col.confidence = 0.5;

            if (col.name.empty()) {
                col.name = "subquery";
            }

            projections.push_back(std::move(col));
            continue;
        }

        // Case 5: CaseExpr
        if (has_key(val, "CaseExpr")) {
            std::vector<std::string> case_cols;
            collect_column_names(val, case_cols);
            for (auto& c : case_cols) {
                col.derived_from.push_back(std::move(c));
            }
            col.expression = "case";
            col.confidence = 0.7;

            if (col.name.empty() && !col.derived_from.empty()) {
                col.name = col.derived_from.front();
            } else if (col.name.empty()) {
                col.name = "case";
            }

            projections.push_back(std::move(col));
            continue;
        }

        // Case 6: TypeCast
        if (has_key(val, "TypeCast")) {
            std::vector<std::string> cast_cols;
            collect_column_names(val, cast_cols);
            for (auto& c : cast_cols) {
                col.derived_from.push_back(std::move(c));
            }
            col.expression = "typecast";
            col.confidence = 0.95;

            if (col.name.empty() && !col.derived_from.empty()) {
                col.name = col.derived_from.front();
            }

            projections.push_back(std::move(col));
            continue;
        }

        // Case 7: A_Const (literal value, e.g., SELECT 1, SELECT 'hello')
        if (has_key(val, "A_Const")) {
            const auto& a_const = val["A_Const"];
            if (has_key(a_const, "ival")) {
                col.expression = "integer_literal";
            } else if (has_key(a_const, "sval")) {
                col.expression = "string_literal";
            } else if (has_key(a_const, "fval")) {
                col.expression = "float_literal";
            } else {
                col.expression = "literal";
            }
            col.confidence = 1.0;

            if (col.name.empty()) {
                col.name = col.expression;
            }

            projections.push_back(std::move(col));
            continue;
        }

        // Case 8: CoalesceExpr
        if (has_key(val, "CoalesceExpr")) {
            std::vector<std::string> coalesce_cols;
            collect_column_names(val, coalesce_cols);
            for (auto& c : coalesce_cols) {
                col.derived_from.push_back(std::move(c));
            }
            col.expression = "coalesce";
            col.confidence = 0.85;

            if (col.name.empty() && !col.derived_from.empty()) {
                col.name = col.derived_from.front();
            } else if (col.name.empty()) {
                col.name = "coalesce";
            }

            projections.push_back(std::move(col));
            continue;
        }

        // Fallback: try to extract any column references from the value expression
        {
            std::vector<std::string> fallback_cols;
            collect_column_names(val, fallback_cols);
            for (auto& c : fallback_cols) {
                col.derived_from.push_back(std::move(c));
            }
            col.expression = "unknown";
            col.confidence = 0.5;

            if (col.name.empty() && !col.derived_from.empty()) {
                col.name = col.derived_from.front();
            } else if (col.name.empty()) {
                col.name = "unknown";
            }

            projections.push_back(std::move(col));
        }
    }

    return projections;
}

// ============================================================================
// extract_filter_columns - Walk WHERE clause and JOIN ON conditions
// ============================================================================

std::vector<ColumnRef> SQLAnalyzer::extract_filter_columns(void* parse_tree) {
    std::vector<ColumnRef> columns;

    json root = parse_json_tree(parse_tree);
    if (root.is_null()) {
        return columns;
    }

    json stmt = get_first_stmt(root);
    if (stmt.is_null()) {
        return columns;
    }

    auto [stmt_type, body] = get_stmt_body(stmt);
    if (body.is_null()) {
        return columns;
    }

    // Extract columns from WHERE clause
    if (has_key(body, "whereClause")) {
        std::vector<std::string> col_names;
        std::vector<std::string> table_qualified;
        walk_expr_for_columns(body["whereClause"], col_names, table_qualified);

        // Use table-qualified names when available, otherwise plain column names
        std::unordered_set<std::string> added;
        for (const auto& tq : table_qualified) {
            if (added.insert(tq).second) {
                size_t dot = tq.find('.');
                ColumnRef ref;
                ref.table = tq.substr(0, dot);
                ref.column = tq.substr(dot + 1);
                columns.push_back(std::move(ref));
            }
        }
        for (const auto& cn : col_names) {
            // Only add if not already added as table-qualified
            bool already_qualified = false;
            for (const auto& tq : table_qualified) {
                size_t dot = tq.find('.');
                if (dot != std::string::npos && tq.substr(dot + 1) == cn) {
                    already_qualified = true;
                    break;
                }
            }
            if (!already_qualified) {
                std::string key = "." + cn;
                if (added.insert(key).second) {
                    ColumnRef ref;
                    ref.column = cn;
                    columns.push_back(std::move(ref));
                }
            }
        }
    }

    // Extract columns from JOIN ON conditions
    if (has_key(body, "fromClause") && body["fromClause"].is_array()) {
        for (const auto& from_item : body["fromClause"]) {
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

    if (has_key(node, "JoinExpr")) {
        const auto& je = node["JoinExpr"];

        // Extract columns from ON condition (quals)
        if (has_key(je, "quals")) {
            std::vector<std::string> col_names;
            std::vector<std::string> table_qualified;
            walk_expr_for_columns(je["quals"], col_names, table_qualified);

            std::unordered_set<std::string> added;
            for (const auto& tq : table_qualified) {
                if (added.insert(tq).second) {
                    size_t dot = tq.find('.');
                    ColumnRef ref;
                    ref.table = tq.substr(0, dot);
                    ref.column = tq.substr(dot + 1);
                    columns.push_back(std::move(ref));
                }
            }
            for (const auto& cn : col_names) {
                bool already_qualified = false;
                for (const auto& tq : table_qualified) {
                    size_t dot = tq.find('.');
                    if (dot != std::string::npos && tq.substr(dot + 1) == cn) {
                        already_qualified = true;
                        break;
                    }
                }
                if (!already_qualified) {
                    std::string key = "." + cn;
                    if (added.insert(key).second) {
                        ColumnRef ref;
                        ref.column = cn;
                        columns.push_back(std::move(ref));
                    }
                }
            }
        }

        // Recurse into left and right args for nested joins
        if (has_key(je, "larg")) {
            extract_join_filter_columns(je["larg"], columns);
        }
        if (has_key(je, "rarg")) {
            extract_join_filter_columns(je["rarg"], columns);
        }
    }
}

// ============================================================================
// extract_write_columns - Walk INSERT/UPDATE column lists
// ============================================================================

std::vector<ColumnRef> SQLAnalyzer::extract_write_columns(void* parse_tree, StatementType type) {
    std::vector<ColumnRef> columns;

    json root = parse_json_tree(parse_tree);
    if (root.is_null()) {
        return columns;
    }

    json stmt = get_first_stmt(root);
    if (stmt.is_null()) {
        return columns;
    }

    if (type == StatementType::INSERT) {
        if (!has_key(stmt, "InsertStmt")) {
            return columns;
        }
        const auto& insert_stmt = stmt["InsertStmt"];

        // Extract column list from "cols" array
        if (has_key(insert_stmt, "cols") && insert_stmt["cols"].is_array()) {
            for (const auto& col_item : insert_stmt["cols"]) {
                if (!has_key(col_item, "ResTarget")) {
                    continue;
                }
                const auto& res_target = col_item["ResTarget"];
                std::string col_name = get_string(res_target, "name");
                if (!col_name.empty()) {
                    ColumnRef ref;
                    ref.column = std::move(col_name);
                    columns.push_back(std::move(ref));
                }
            }
        }
    } else if (type == StatementType::UPDATE) {
        if (!has_key(stmt, "UpdateStmt")) {
            return columns;
        }
        const auto& update_stmt = stmt["UpdateStmt"];

        // Extract SET target columns from "targetList"
        if (has_key(update_stmt, "targetList") && update_stmt["targetList"].is_array()) {
            for (const auto& target_item : update_stmt["targetList"]) {
                if (!has_key(target_item, "ResTarget")) {
                    continue;
                }
                const auto& res_target = target_item["ResTarget"];
                std::string col_name = get_string(res_target, "name");
                if (!col_name.empty()) {
                    ColumnRef ref;
                    ref.column = std::move(col_name);
                    columns.push_back(std::move(ref));
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
    size_t dot_pos = col.find('.');
    if (dot_pos == std::string::npos) {
        return col; // No prefix
    }

    std::string prefix = col.substr(0, dot_pos);
    std::string col_name = col.substr(dot_pos + 1);

    // Resolve alias to table name
    auto it = aliases.find(prefix);
    if (it != aliases.end()) {
        return it->second + "." + col_name;
    }

    return col; // Prefix is already table name
}

// ============================================================================
// has_aggregation - Detect aggregate functions in AST
// ============================================================================

bool SQLAnalyzer::has_aggregation(void* parse_tree) {
    json root = parse_json_tree(parse_tree);
    if (root.is_null()) {
        return false;
    }

    json stmt = get_first_stmt(root);
    if (stmt.is_null()) {
        return false;
    }

    return walk_for_aggregation(stmt);
}

// ============================================================================
// has_subquery - Detect SubLink/RangeSubselect nodes
// ============================================================================

bool SQLAnalyzer::has_subquery(void* parse_tree) {
    json root = parse_json_tree(parse_tree);
    if (root.is_null()) {
        return false;
    }

    json stmt = get_first_stmt(root);
    if (stmt.is_null()) {
        return false;
    }

    return walk_for_subquery(stmt);
}

// ============================================================================
// has_join - Detect JoinExpr nodes
// ============================================================================

bool SQLAnalyzer::has_join(void* parse_tree) {
    json root = parse_json_tree(parse_tree);
    if (root.is_null()) {
        return false;
    }

    json stmt = get_first_stmt(root);
    if (stmt.is_null()) {
        return false;
    }

    return walk_for_join(stmt);
}

// ============================================================================
// extract_limit - Get LIMIT value from SelectStmt
// ============================================================================

std::optional<int64_t> SQLAnalyzer::extract_limit(void* parse_tree) {
    json root = parse_json_tree(parse_tree);
    if (root.is_null()) {
        return std::nullopt;
    }

    json stmt = get_first_stmt(root);
    if (stmt.is_null()) {
        return std::nullopt;
    }

    auto [stmt_type, body] = get_stmt_body(stmt);
    if (stmt_type != "SelectStmt" || body.is_null()) {
        return std::nullopt;
    }

    if (!has_key(body, "limitCount")) {
        return std::nullopt;
    }

    const auto& limit_node = body["limitCount"];

    // Case 1: A_Const with Integer value (e.g., LIMIT 10)
    // libpg_query v17 format: {"A_Const": {"ival": {"ival": 10}}}
    // or older: {"A_Const": {"val": {"Integer": {"ival": 10}}}}
    // or direct: {"Integer": {"ival": 10}}
    if (has_key(limit_node, "A_Const")) {
        const auto& a_const = limit_node["A_Const"];

        // v17 format: ival is an object with ival inside
        if (has_key(a_const, "ival")) {
            const auto& ival_node = a_const["ival"];
            if (ival_node.is_object()) {
                auto val = get_int(ival_node, "ival");
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
        if (has_key(a_const, "val")) {
            const auto& val = a_const["val"];
            if (has_key(val, "Integer")) {
                return get_int(val["Integer"], "ival");
            }
        }
    }

    // Direct Integer node
    if (has_key(limit_node, "Integer")) {
        return get_int(limit_node["Integer"], "ival");
    }

    return std::nullopt;
}

} // namespace sqlproxy
