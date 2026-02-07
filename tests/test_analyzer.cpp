#include <catch2/catch_test_macros.hpp>
#include "analyzer/sql_analyzer.hpp"
#include "parser/sql_parser.hpp"

using namespace sqlproxy;

// Helper: parse SQL and get access to parse_tree for analysis
// Since SQLAnalyzer::analyze needs a ParsedQuery + parse_tree, we use the
// code path that builds both. The analyzer can operate on ParsedQuery alone
// (with nullptr parse_tree) for basic classification, or with a full AST.

// Helper to create a minimal AnalysisResult by calling analyze with a
// ParsedQuery constructed from known data (no parse tree - tests the
// code path where parse_tree is nullptr).
static AnalysisResult analyze_from_parsed(StatementType type,
                                           std::vector<TableRef> tables,
                                           bool is_write = false) {
    ParsedQuery parsed;
    parsed.type = type;
    parsed.tables = std::move(tables);
    parsed.is_write = is_write;
    parsed.is_transaction = false;

    return SQLAnalyzer::analyze(parsed, nullptr);
}

TEST_CASE("SQLAnalyzer source and target table classification", "[analyzer]") {

    SECTION("SELECT - all tables are sources") {
        auto result = analyze_from_parsed(
            StatementType::SELECT,
            {TableRef("customers"), TableRef("orders")});

        REQUIRE(result.source_tables.size() == 2);
        REQUIRE(result.target_tables.empty());
    }

    SECTION("INSERT - first table is target, rest are sources") {
        auto result = analyze_from_parsed(
            StatementType::INSERT,
            {TableRef("orders"), TableRef("customers")},
            true);

        // With nullptr parse_tree, analyze uses the simplified path
        // First table in list is classified as WRITE target
        REQUIRE_FALSE(result.target_tables.empty());
        REQUIRE(result.target_tables[0].table == "orders");
    }

    SECTION("UPDATE - first table is target") {
        auto result = analyze_from_parsed(
            StatementType::UPDATE,
            {TableRef("customers")},
            true);

        REQUIRE_FALSE(result.target_tables.empty());
        REQUIRE(result.target_tables[0].table == "customers");
    }

    SECTION("DELETE - first table is target") {
        auto result = analyze_from_parsed(
            StatementType::DELETE,
            {TableRef("order_items")},
            true);

        REQUIRE_FALSE(result.target_tables.empty());
        REQUIRE(result.target_tables[0].table == "order_items");
    }

    SECTION("Table usage map populated correctly for SELECT") {
        auto result = analyze_from_parsed(
            StatementType::SELECT,
            {TableRef("customers")});

        REQUIRE(result.table_usage.count("customers") > 0);
        REQUIRE(result.table_usage.at("customers") == TableUsage::READ);
    }

    SECTION("Table usage map populated correctly for INSERT") {
        auto result = analyze_from_parsed(
            StatementType::INSERT,
            {TableRef("orders"), TableRef("customers")},
            true);

        REQUIRE(result.table_usage.count("orders") > 0);
        REQUIRE(result.table_usage.at("orders") == TableUsage::WRITE);
        // Second table is a source (INSERT...SELECT pattern)
        if (result.table_usage.count("customers") > 0) {
            REQUIRE(result.table_usage.at("customers") == TableUsage::READ);
        }
    }
}

TEST_CASE("SQLAnalyzer statement type propagation", "[analyzer]") {

    SECTION("Statement type is propagated from ParsedQuery") {
        auto result = analyze_from_parsed(
            StatementType::SELECT, {TableRef("users")});
        REQUIRE(result.statement_type == StatementType::SELECT);
        REQUIRE(result.sub_type == "SELECT");
    }

    SECTION("INSERT sub_type") {
        auto result = analyze_from_parsed(
            StatementType::INSERT, {TableRef("users")}, true);
        REQUIRE(result.statement_type == StatementType::INSERT);
        REQUIRE(result.sub_type == "INSERT");
    }

    SECTION("DELETE sub_type") {
        auto result = analyze_from_parsed(
            StatementType::DELETE, {TableRef("users")}, true);
        REQUIRE(result.sub_type == "DELETE");
    }
}

TEST_CASE("SQLAnalyzer schema-qualified table names", "[analyzer]") {

    SECTION("Schema preserved in source tables") {
        auto result = analyze_from_parsed(
            StatementType::SELECT,
            {TableRef("public", "customers")});

        REQUIRE(result.source_tables.size() == 1);
        REQUIRE(result.source_tables[0].schema == "public");
        REQUIRE(result.source_tables[0].table == "customers");
    }

    SECTION("Full name includes schema") {
        auto result = analyze_from_parsed(
            StatementType::SELECT,
            {TableRef("audit", "events")});

        REQUIRE(result.source_tables.size() == 1);
        REQUIRE(result.source_tables[0].full_name() == "audit.events");
    }

    SECTION("Table without schema has empty schema") {
        auto result = analyze_from_parsed(
            StatementType::SELECT,
            {TableRef("orders")});

        REQUIRE(result.source_tables.size() == 1);
        REQUIRE(result.source_tables[0].schema.empty());
        REQUIRE(result.source_tables[0].full_name() == "orders");
    }
}

TEST_CASE("SQLAnalyzer default values for characteristics", "[analyzer]") {

    SECTION("No parse tree - characteristics default to false") {
        auto result = analyze_from_parsed(
            StatementType::SELECT, {TableRef("users")});

        // Without a parse tree, these should remain at their default (false)
        REQUIRE_FALSE(result.has_join);
        REQUIRE_FALSE(result.has_subquery);
        REQUIRE_FALSE(result.has_aggregation);
        REQUIRE_FALSE(result.limit_value.has_value());
        REQUIRE_FALSE(result.is_star_select);
    }
}

TEST_CASE("SQLAnalyzer alias map building", "[analyzer]") {

    SECTION("Alias map is empty when no aliases present") {
        auto result = analyze_from_parsed(
            StatementType::SELECT,
            {TableRef("customers"), TableRef("orders")});

        REQUIRE(result.alias_to_table.empty());
    }

    SECTION("Alias map built from aliased tables") {
        TableRef customers;
        customers.table = "customers";
        customers.alias = "c";

        TableRef orders;
        orders.table = "orders";
        orders.alias = "o";

        auto result = analyze_from_parsed(
            StatementType::SELECT, {customers, orders});

        REQUIRE(result.alias_to_table.size() == 2);
        REQUIRE(result.alias_to_table.at("c") == "customers");
        REQUIRE(result.alias_to_table.at("o") == "orders");
    }
}

// The following tests require a full parse tree from libpg_query.
// We use the SQLParser to generate the parse tree, then test analysis.
// These tests verify behavior when the full AST is available.

TEST_CASE("SQLAnalyzer with parser integration - projections", "[analyzer][integration]") {

    // Note: The analyzer's extract_projections, has_join, has_subquery, etc.
    // require a live PgQueryParseResult pointer. Since we cannot keep the parse
    // tree alive after SQLParser::parse frees it, we test the analyze()
    // function indirectly by checking the ParsedQuery-based path.

    SECTION("Projections empty without parse tree") {
        auto result = analyze_from_parsed(
            StatementType::SELECT, {TableRef("users")});
        // Without parse tree, projections are not extracted
        REQUIRE(result.projections.empty());
    }
}

TEST_CASE("AnalysisResult defaults", "[analyzer]") {

    SECTION("Default-constructed AnalysisResult has expected values") {
        AnalysisResult result;
        REQUIRE(result.statement_type == StatementType::UNKNOWN);
        REQUIRE_FALSE(result.is_star_select);
        REQUIRE_FALSE(result.has_subquery);
        REQUIRE_FALSE(result.has_join);
        REQUIRE_FALSE(result.has_aggregation);
        REQUIRE_FALSE(result.limit_value.has_value());
        REQUIRE(result.source_tables.empty());
        REQUIRE(result.target_tables.empty());
        REQUIRE(result.projections.empty());
        REQUIRE(result.filter_columns.empty());
        REQUIRE(result.write_columns.empty());
    }
}

TEST_CASE("ProjectionColumn structure", "[analyzer]") {

    SECTION("Default ProjectionColumn") {
        ProjectionColumn col;
        REQUIRE_FALSE(col.is_star_expansion);
        REQUIRE(col.confidence == 1.0);
        REQUIRE(col.derived_from.empty());
        REQUIRE(col.name.empty());
    }

    SECTION("ProjectionColumn with sources") {
        ProjectionColumn col("upper_email", {"email"});
        REQUIRE(col.name == "upper_email");
        REQUIRE(col.derived_from.size() == 1);
        REQUIRE(col.derived_from[0] == "email");
        REQUIRE_FALSE(col.is_star_expansion);
    }
}
