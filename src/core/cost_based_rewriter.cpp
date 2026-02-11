#include "core/cost_based_rewriter.hpp"

#include <algorithm>
#include <format>

namespace sqlproxy {

CostBasedRewriter::CostBasedRewriter() : CostBasedRewriter(Config{}) {}

CostBasedRewriter::CostBasedRewriter(Config config)
    : config_(std::move(config)) {}

void CostBasedRewriter::set_schema_cache(std::shared_ptr<SchemaCache> cache) {
    schema_cache_ = std::move(cache);
}

CostBasedRewriter::RewriteResult CostBasedRewriter::rewrite_if_expensive(
    const std::string& sql, const AnalysisResult& analysis) const {

    if (!config_.enabled) return {};

    // Rule 1: Restrict SELECT * to explicit columns
    if (analysis.is_star_select) {
        const auto result = try_restrict_star_select(sql, analysis);
        if (result.rewritten) return result;
    }

    // Rule 2: Add default LIMIT to unbounded SELECT
    if (analysis.statement_type == StatementType::SELECT && !analysis.limit_value.has_value()) {
        const auto result = try_add_default_limit(sql, analysis);
        if (result.rewritten) return result;
    }

    return {};
}

CostBasedRewriter::RewriteResult CostBasedRewriter::try_restrict_star_select(
    const std::string& sql, const AnalysisResult& analysis) const {

    if (!schema_cache_) return {};

    // Get the primary table from the query
    if (analysis.source_tables.empty()) return {};
    const auto& table_name = analysis.source_tables[0].table;

    const auto table_meta = schema_cache_->get_table(table_name);
    if (!table_meta) return {};

    // Only rewrite if the table has many columns (expensive SELECT *)
    if (table_meta->columns.size() <= config_.max_columns_for_star) return {};

    // Build explicit column list
    std::string columns;
    for (size_t i = 0; i < table_meta->columns.size(); ++i) {
        if (i > 0) columns += ", ";
        columns += table_meta->columns[i].name;
    }

    // Find "SELECT *" or "select *" and replace with column list
    std::string new_sql = sql;
    // Case-insensitive search for "SELECT" followed by optional whitespace and "*"
    for (size_t i = 0; i + 7 < new_sql.size(); ++i) {
        const auto chunk = new_sql.substr(i, 6);
        bool is_select = true;
        const std::string select_kw = "SELECT";
        for (size_t j = 0; j < 6; ++j) {
            if (std::toupper(static_cast<unsigned char>(chunk[j])) != select_kw[j]) {
                is_select = false;
                break;
            }
        }
        if (!is_select) continue;

        // Skip whitespace after SELECT
        size_t pos = i + 6;
        while (pos < new_sql.size() && std::isspace(static_cast<unsigned char>(new_sql[pos]))) ++pos;

        if (pos < new_sql.size() && new_sql[pos] == '*') {
            // Replace "SELECT ... *" with "SELECT col1, col2, ..."
            new_sql = new_sql.substr(0, i) + "SELECT " + columns + new_sql.substr(pos + 1);
            return {true, std::move(new_sql), "restrict_star_select"};
        }
    }

    return {};
}

CostBasedRewriter::RewriteResult CostBasedRewriter::try_add_default_limit(
    const std::string& sql, const AnalysisResult& analysis) const {

    // Don't add LIMIT to aggregations (they naturally return few rows)
    if (analysis.has_aggregation) return {};

    // Don't add LIMIT to subquery-containing queries (complex to rewrite safely)
    if (analysis.has_subquery) return {};

    // Add LIMIT 1000 to unbounded SELECT
    std::string new_sql = sql;

    // Strip trailing semicolons and whitespace
    while (!new_sql.empty() &&
           (new_sql.back() == ';' || std::isspace(static_cast<unsigned char>(new_sql.back())))) {
        new_sql.pop_back();
    }

    new_sql += " LIMIT 1000";

    return {true, std::move(new_sql), "add_default_limit"};
}

} // namespace sqlproxy
