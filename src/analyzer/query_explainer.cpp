#include "analyzer/query_explainer.hpp"
#include "analyzer/sql_analyzer.hpp"
#include "core/types.hpp"

#include <format>

namespace sqlproxy {

QueryExplainer::Explanation QueryExplainer::explain(const AnalysisResult& analysis) {
    Explanation exp;

    // Statement type
    exp.statement_type = statement_type_to_string(analysis.statement_type);

    // Tables read
    for (const auto& t : analysis.source_tables) {
        exp.tables_read.push_back(t.full_name());
    }

    // Tables written
    for (const auto& t : analysis.target_tables) {
        exp.tables_written.push_back(t.full_name());
    }

    // Columns selected (from projections)
    for (const auto& p : analysis.projections) {
        exp.columns_selected.push_back(p.name);
    }

    // Columns filtered
    for (const auto& c : analysis.filter_columns) {
        exp.columns_filtered.push_back(c.column);
    }

    // Columns written
    for (const auto& c : analysis.write_columns) {
        exp.columns_written.push_back(c.column);
    }

    // Characteristics
    exp.characteristics.has_join = analysis.has_join;
    exp.characteristics.has_subquery = analysis.has_subquery;
    exp.characteristics.has_aggregation = analysis.has_aggregation;
    exp.characteristics.has_star_select = analysis.is_star_select;
    exp.characteristics.limit = analysis.limit_value;

    // Build human-readable summary
    std::string summary;
    summary.reserve(256);

    summary += "This ";
    summary += exp.statement_type;

    switch (analysis.statement_type) {
        case StatementType::SELECT: {
            // "This SELECT reads from 'customers', filtering by 'id', returning: name, email"
            if (!exp.tables_read.empty()) {
                summary += " reads from ";
                for (size_t i = 0; i < exp.tables_read.size(); ++i) {
                    if (i > 0) summary += ", ";
                    summary += '\'';
                    summary += exp.tables_read[i];
                    summary += '\'';
                }
            }
            if (!exp.columns_filtered.empty()) {
                summary += ", filtering by ";
                for (size_t i = 0; i < exp.columns_filtered.size(); ++i) {
                    if (i > 0) summary += ", ";
                    summary += '\'';
                    summary += exp.columns_filtered[i];
                    summary += '\'';
                }
            }
            if (!exp.columns_selected.empty()) {
                summary += ", returning: ";
                for (size_t i = 0; i < exp.columns_selected.size(); ++i) {
                    if (i > 0) summary += ", ";
                    summary += exp.columns_selected[i];
                }
            }
            break;
        }
        case StatementType::INSERT: {
            // "This INSERT writes to 'orders' columns: customer_id, product, quantity"
            if (!exp.tables_written.empty()) {
                summary += " writes to ";
                for (size_t i = 0; i < exp.tables_written.size(); ++i) {
                    if (i > 0) summary += ", ";
                    summary += '\'';
                    summary += exp.tables_written[i];
                    summary += '\'';
                }
            }
            if (!exp.columns_written.empty()) {
                summary += " columns: ";
                for (size_t i = 0; i < exp.columns_written.size(); ++i) {
                    if (i > 0) summary += ", ";
                    summary += exp.columns_written[i];
                }
            }
            break;
        }
        case StatementType::UPDATE: {
            // "This UPDATE modifies 'customers' columns: name, email, filtering by 'id'"
            if (!exp.tables_written.empty()) {
                summary += " modifies ";
                for (size_t i = 0; i < exp.tables_written.size(); ++i) {
                    if (i > 0) summary += ", ";
                    summary += '\'';
                    summary += exp.tables_written[i];
                    summary += '\'';
                }
            }
            if (!exp.columns_written.empty()) {
                summary += " columns: ";
                for (size_t i = 0; i < exp.columns_written.size(); ++i) {
                    if (i > 0) summary += ", ";
                    summary += exp.columns_written[i];
                }
            }
            if (!exp.columns_filtered.empty()) {
                summary += ", filtering by ";
                for (size_t i = 0; i < exp.columns_filtered.size(); ++i) {
                    if (i > 0) summary += ", ";
                    summary += '\'';
                    summary += exp.columns_filtered[i];
                    summary += '\'';
                }
            }
            break;
        }
        case StatementType::DELETE: {
            // "This DELETE removes from 'customers', filtering by 'id'"
            if (!exp.tables_written.empty()) {
                summary += " removes from ";
                for (size_t i = 0; i < exp.tables_written.size(); ++i) {
                    if (i > 0) summary += ", ";
                    summary += '\'';
                    summary += exp.tables_written[i];
                    summary += '\'';
                }
            }
            if (!exp.columns_filtered.empty()) {
                summary += ", filtering by ";
                for (size_t i = 0; i < exp.columns_filtered.size(); ++i) {
                    if (i > 0) summary += ", ";
                    summary += '\'';
                    summary += exp.columns_filtered[i];
                    summary += '\'';
                }
            }
            break;
        }
        default: {
            // Generic summary for DDL or other statement types
            if (!exp.tables_written.empty()) {
                summary += " targets ";
                for (size_t i = 0; i < exp.tables_written.size(); ++i) {
                    if (i > 0) summary += ", ";
                    summary += '\'';
                    summary += exp.tables_written[i];
                    summary += '\'';
                }
            } else if (!exp.tables_read.empty()) {
                summary += " references ";
                for (size_t i = 0; i < exp.tables_read.size(); ++i) {
                    if (i > 0) summary += ", ";
                    summary += '\'';
                    summary += exp.tables_read[i];
                    summary += '\'';
                }
            }
            break;
        }
    }

    exp.summary = std::move(summary);
    return exp;
}

} // namespace sqlproxy
