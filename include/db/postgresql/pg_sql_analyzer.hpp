#pragma once

#include "analyzer/sql_analyzer.hpp"

namespace sqlproxy {

/**
 * @brief PostgreSQL SQL Analyzer
 *
 * Thin wrapper around SQLAnalyzer that makes its PostgreSQL-specific
 * nature explicit in the type system. Currently delegates to the
 * static SQLAnalyzer methods which use libpg_query AST format.
 *
 * When other backends need analyzers, this class ensures
 * PG-specific analysis is cleanly separated.
 */
class PgSqlAnalyzer {
public:
    /**
     * @brief Analyze parsed query using PostgreSQL AST
     * @param parsed ParsedQuery from PgSqlParser
     * @param parse_tree libpg_query parse tree (opaque pointer)
     * @return Analysis result
     */
    static AnalysisResult analyze(const ParsedQuery& parsed, void* parse_tree) {
        return SQLAnalyzer::analyze(parsed, parse_tree);
    }
};

} // namespace sqlproxy
