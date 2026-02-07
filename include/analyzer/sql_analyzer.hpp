#pragma once

#include "core/types.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>

namespace sqlproxy {

/**
 * @brief Column projection with derived tracking
 *
 * For SELECT columns, tracks if the column is derived from other columns.
 * Critical for PII classification: UPPER(email) is still PII.
 */
struct ProjectionColumn {
    std::string name;                       // Output column name
    std::string expression;                 // Original expression
    std::vector<std::string> derived_from;  // Source columns
    bool is_star_expansion;                 // Part of SELECT *
    double confidence;                      // Confidence in derivation (1.0 = direct)

    ProjectionColumn()
        : is_star_expansion(false), confidence(1.0) {}

    ProjectionColumn(std::string n, std::vector<std::string> sources)
        : name(std::move(n)),
          derived_from(std::move(sources)),
          is_star_expansion(false),
          confidence(1.0) {}
};

/**
 * @brief Table usage tracking
 */
enum class TableUsage {
    READ,       // SELECT FROM, JOIN
    WRITE,      // INSERT INTO, UPDATE
    BOTH        // INSERT...SELECT
};

/**
 * @brief Analysis result from AST walk
 *
 * Single-pass extraction of all metadata needed by downstream stages:
 * - Policy engine: tables + statement type
 * - Executor: statement branching
 * - Classifier: projections with derived_from
 * - Audit: complete metadata
 */
struct AnalysisResult {
    // Statement classification
    StatementType statement_type;
    std::string sub_type;                   // "SELECT", "INSERT", "UPDATE", etc.

    // Table references with usage
    std::vector<TableRef> source_tables;    // Tables data is READ from
    std::vector<TableRef> target_tables;    // Tables data is WRITTEN to
    std::unordered_map<std::string, TableUsage> table_usage;

    // Column references
    std::vector<ProjectionColumn> projections;  // SELECT columns (with derived_from)
    std::vector<ColumnRef> write_columns;       // INSERT/UPDATE target columns
    std::vector<ColumnRef> filter_columns;      // WHERE/JOIN ON columns

    // Query characteristics
    bool is_star_select;                    // SELECT *
    bool has_subquery;
    bool has_join;
    bool has_aggregation;
    std::optional<int64_t> limit_value;

    // Alias mapping (for resolution)
    std::unordered_map<std::string, std::string> alias_to_table;

    AnalysisResult()
        : statement_type(StatementType::UNKNOWN),
          is_star_select(false),
          has_subquery(false),
          has_join(false),
          has_aggregation(false) {}
};

/**
 * @brief SQL Analyzer - single-pass AST walker
 *
 * Walks libpg_query AST once and extracts all metadata.
 * Result is embedded in parse cache entry for zero cost on cache hit.
 *
 * Key features:
 * - Alias resolution: a.name → customers.name
 * - derived_from tracking: UPPER(email) → {derived_from: ["email"]}
 * - Table usage classification: READ vs WRITE
 * - SELECT * expansion via schema cache
 *
 * Performance: ~5μs for typical query (on cache miss)
 */
class SQLAnalyzer {
public:
    /**
     * @brief Analyze parsed query
     * @param parsed ParsedQuery from parser
     * @param parse_tree libpg_query parse tree (opaque pointer)
     * @return Analysis result
     */
    static AnalysisResult analyze(const ParsedQuery& parsed, void* parse_tree);

private:
    /**
     * @brief Extract table references from AST
     */
    static std::vector<TableRef> extract_tables(void* parse_tree, StatementType type);

    /**
     * @brief Extract SELECT projections with derived_from tracking
     */
    static std::vector<ProjectionColumn> extract_projections(void* parse_tree);

    /**
     * @brief Extract columns from WHERE clause
     */
    static std::vector<ColumnRef> extract_filter_columns(void* parse_tree);

    /**
     * @brief Extract columns from INSERT/UPDATE statements
     */
    static std::vector<ColumnRef> extract_write_columns(void* parse_tree, StatementType type);

    /**
     * @brief Build alias-to-table mapping
     */
    static std::unordered_map<std::string, std::string> build_alias_map(
        const std::vector<TableRef>& tables);

    /**
     * @brief Resolve column reference using alias map
     */
    static std::string resolve_column(const std::string& col,
                                       const std::unordered_map<std::string, std::string>& aliases);

    /**
     * @brief Detect if query has aggregation
     */
    static bool has_aggregation(void* parse_tree);

    /**
     * @brief Detect if query has subquery
     */
    static bool has_subquery(void* parse_tree);

    /**
     * @brief Detect if query has joins
     */
    static bool has_join(void* parse_tree);

    /**
     * @brief Extract LIMIT value if present
     */
    static std::optional<int64_t> extract_limit(void* parse_tree);
};

} // namespace sqlproxy
