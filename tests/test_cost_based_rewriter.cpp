#include <catch2/catch_test_macros.hpp>
#include "core/cost_based_rewriter.hpp"

using namespace sqlproxy;

TEST_CASE("CostBasedRewriter - disabled", "[cost_rewrite]") {
    CostBasedRewriter rewriter;
    REQUIRE_FALSE(rewriter.is_enabled());

    AnalysisResult analysis;
    analysis.is_star_select = true;
    auto result = rewriter.rewrite_if_expensive("SELECT * FROM big_table", analysis);
    REQUIRE_FALSE(result.rewritten);
}

TEST_CASE("CostBasedRewriter - add default limit", "[cost_rewrite]") {
    CostBasedRewriter::Config cfg;
    cfg.enabled = true;
    CostBasedRewriter rewriter(cfg);

    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    // No limit_value set → unbounded

    auto result = rewriter.rewrite_if_expensive("SELECT id, name FROM customers", analysis);
    REQUIRE(result.rewritten);
    REQUIRE(result.rule_applied == "add_default_limit");
    REQUIRE(result.new_sql == "SELECT id, name FROM customers LIMIT 1000");
}

TEST_CASE("CostBasedRewriter - no limit for aggregation", "[cost_rewrite]") {
    CostBasedRewriter::Config cfg;
    cfg.enabled = true;
    CostBasedRewriter rewriter(cfg);

    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    analysis.has_aggregation = true;

    auto result = rewriter.rewrite_if_expensive("SELECT COUNT(*) FROM customers", analysis);
    REQUIRE_FALSE(result.rewritten);
}

TEST_CASE("CostBasedRewriter - skip if limit exists", "[cost_rewrite]") {
    CostBasedRewriter::Config cfg;
    cfg.enabled = true;
    CostBasedRewriter rewriter(cfg);

    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    analysis.limit_value = 50;

    auto result = rewriter.rewrite_if_expensive("SELECT * FROM customers LIMIT 50", analysis);
    REQUIRE_FALSE(result.rewritten);
}

TEST_CASE("CostBasedRewriter - restrict star select with schema", "[cost_rewrite]") {
    CostBasedRewriter::Config cfg;
    cfg.enabled = true;
    cfg.max_columns_for_star = 3;  // Only rewrite tables with >3 columns
    CostBasedRewriter rewriter(cfg);

    // Set up a schema cache with a wide table
    auto cache = std::make_shared<SchemaCache>();
    auto schema = std::make_shared<SchemaMap>();
    auto table = std::make_shared<TableMetadata>();
    table->name = "wide_table";
    table->columns.emplace_back("id", "integer");
    table->columns.emplace_back("name", "text");
    table->columns.emplace_back("email", "text");
    table->columns.emplace_back("phone", "text");
    table->columns.emplace_back("address", "text");
    (*schema)["wide_table"] = table;

    // Use loader to populate cache
    cache->set_loader([&schema](const std::string&) -> SchemaMap {
        return *schema;
    });
    cache->reload("");

    rewriter.set_schema_cache(cache);

    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    analysis.is_star_select = true;
    analysis.source_tables.emplace_back("wide_table");

    auto result = rewriter.rewrite_if_expensive("SELECT * FROM wide_table", analysis);
    REQUIRE(result.rewritten);
    REQUIRE(result.rule_applied == "restrict_star_select");
    REQUIRE(result.new_sql == "SELECT id, name, email, phone, address FROM wide_table");
}

TEST_CASE("CostBasedRewriter - no restrict for narrow table", "[cost_rewrite]") {
    CostBasedRewriter::Config cfg;
    cfg.enabled = true;
    cfg.max_columns_for_star = 10;  // Table has fewer columns than threshold
    CostBasedRewriter rewriter(cfg);

    auto cache = std::make_shared<SchemaCache>();
    auto schema = std::make_shared<SchemaMap>();
    auto table = std::make_shared<TableMetadata>();
    table->name = "narrow_table";
    table->columns.emplace_back("id", "integer");
    table->columns.emplace_back("name", "text");
    (*schema)["narrow_table"] = table;

    cache->set_loader([&schema](const std::string&) -> SchemaMap {
        return *schema;
    });
    cache->reload("");

    rewriter.set_schema_cache(cache);

    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    analysis.is_star_select = true;
    analysis.source_tables.emplace_back("narrow_table");
    // No limit → should fall through to add_default_limit

    auto result = rewriter.rewrite_if_expensive("SELECT * FROM narrow_table", analysis);
    REQUIRE(result.rewritten);
    REQUIRE(result.rule_applied == "add_default_limit");
}

TEST_CASE("CostBasedRewriter - strip trailing semicolon", "[cost_rewrite]") {
    CostBasedRewriter::Config cfg;
    cfg.enabled = true;
    CostBasedRewriter rewriter(cfg);

    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;

    auto result = rewriter.rewrite_if_expensive("SELECT id FROM orders;", analysis);
    REQUIRE(result.rewritten);
    REQUIRE(result.new_sql == "SELECT id FROM orders LIMIT 1000");
}
