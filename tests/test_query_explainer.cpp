#include <catch2/catch_test_macros.hpp>
#include "analyzer/query_explainer.hpp"
#include "analyzer/sql_analyzer.hpp"

using namespace sqlproxy;

// Helper to build a minimal AnalysisResult for a SELECT
static AnalysisResult make_select(const std::string& table,
                                  const std::vector<std::string>& columns = {},
                                  const std::vector<std::string>& filters = {}) {
    AnalysisResult a;
    a.statement_type = StatementType::SELECT;
    a.sub_type = "SELECT";
    a.source_tables.emplace_back(table);
    a.table_usage[table] = TableUsage::READ;

    for (const auto& col : columns) {
        ProjectionColumn p;
        p.name = col;
        p.derived_from.push_back(col);
        p.confidence = 1.0;
        a.projections.push_back(std::move(p));
    }

    for (const auto& f : filters) {
        a.filter_columns.emplace_back(f);
    }

    return a;
}

// Helper to build a minimal AnalysisResult for an INSERT
static AnalysisResult make_insert(const std::string& table,
                                  const std::vector<std::string>& write_cols) {
    AnalysisResult a;
    a.statement_type = StatementType::INSERT;
    a.sub_type = "INSERT";
    a.target_tables.emplace_back(table);
    a.table_usage[table] = TableUsage::WRITE;

    for (const auto& c : write_cols) {
        a.write_columns.emplace_back(c);
    }

    return a;
}

// Helper to build a minimal AnalysisResult for a DELETE
static AnalysisResult make_delete(const std::string& table,
                                  const std::vector<std::string>& filters = {}) {
    AnalysisResult a;
    a.statement_type = StatementType::DELETE;
    a.sub_type = "DELETE";
    a.target_tables.emplace_back(table);
    a.table_usage[table] = TableUsage::WRITE;

    for (const auto& f : filters) {
        a.filter_columns.emplace_back(f);
    }

    return a;
}

TEST_CASE("QueryExplainer: simple SELECT", "[query_explainer]") {
    auto analysis = make_select("customers", {"name", "email"});
    auto explanation = QueryExplainer::explain(analysis);

    CHECK(explanation.statement_type == "SELECT");
    CHECK(explanation.tables_read.size() == 1);
    CHECK(explanation.tables_read[0] == "customers");
    CHECK(explanation.tables_written.empty());
    CHECK(explanation.columns_selected.size() == 2);
    CHECK(explanation.columns_selected[0] == "name");
    CHECK(explanation.columns_selected[1] == "email");
    CHECK(explanation.columns_filtered.empty());
    CHECK_FALSE(explanation.characteristics.has_join);
    CHECK_FALSE(explanation.characteristics.has_subquery);
    CHECK_FALSE(explanation.characteristics.has_aggregation);
    CHECK_FALSE(explanation.characteristics.has_star_select);
    CHECK_FALSE(explanation.characteristics.limit.has_value());

    // Summary should mention the table
    CHECK(explanation.summary.find("customers") != std::string::npos);
    CHECK(explanation.summary.find("SELECT") != std::string::npos);
}

TEST_CASE("QueryExplainer: SELECT with filters and joins", "[query_explainer]") {
    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    analysis.sub_type = "SELECT";
    analysis.source_tables.emplace_back("customers");
    analysis.source_tables.emplace_back("orders");
    analysis.table_usage["customers"] = TableUsage::READ;
    analysis.table_usage["orders"] = TableUsage::READ;

    ProjectionColumn p1;
    p1.name = "name";
    p1.derived_from.push_back("name");
    analysis.projections.push_back(std::move(p1));

    ProjectionColumn p2;
    p2.name = "total";
    p2.derived_from.push_back("total");
    analysis.projections.push_back(std::move(p2));

    analysis.filter_columns.emplace_back("id");
    analysis.filter_columns.emplace_back("status");
    analysis.has_join = true;
    analysis.has_aggregation = true;
    analysis.limit_value = 100;

    auto explanation = QueryExplainer::explain(analysis);

    CHECK(explanation.statement_type == "SELECT");
    CHECK(explanation.tables_read.size() == 2);
    CHECK(explanation.columns_filtered.size() == 2);
    CHECK(explanation.characteristics.has_join);
    CHECK(explanation.characteristics.has_aggregation);
    CHECK(explanation.characteristics.limit.has_value());
    CHECK(explanation.characteristics.limit.value() == 100);

    // Summary should mention both tables
    CHECK(explanation.summary.find("customers") != std::string::npos);
    CHECK(explanation.summary.find("orders") != std::string::npos);
    CHECK(explanation.summary.find("filtering by") != std::string::npos);
}

TEST_CASE("QueryExplainer: INSERT", "[query_explainer]") {
    auto analysis = make_insert("orders", {"customer_id", "product", "quantity"});
    auto explanation = QueryExplainer::explain(analysis);

    CHECK(explanation.statement_type == "INSERT");
    CHECK(explanation.tables_written.size() == 1);
    CHECK(explanation.tables_written[0] == "orders");
    CHECK(explanation.tables_read.empty());
    CHECK(explanation.columns_written.size() == 3);
    CHECK(explanation.columns_written[0] == "customer_id");
    CHECK(explanation.columns_written[1] == "product");
    CHECK(explanation.columns_written[2] == "quantity");

    // Summary should mention target table and columns
    CHECK(explanation.summary.find("INSERT") != std::string::npos);
    CHECK(explanation.summary.find("orders") != std::string::npos);
    CHECK(explanation.summary.find("customer_id") != std::string::npos);
}

TEST_CASE("QueryExplainer: DELETE", "[query_explainer]") {
    auto analysis = make_delete("customers", {"id"});
    auto explanation = QueryExplainer::explain(analysis);

    CHECK(explanation.statement_type == "DELETE");
    CHECK(explanation.tables_written.size() == 1);
    CHECK(explanation.tables_written[0] == "customers");
    CHECK(explanation.columns_filtered.size() == 1);
    CHECK(explanation.columns_filtered[0] == "id");

    // Summary should mention removal from the table
    CHECK(explanation.summary.find("DELETE") != std::string::npos);
    CHECK(explanation.summary.find("customers") != std::string::npos);
    CHECK(explanation.summary.find("filtering by") != std::string::npos);
}

TEST_CASE("QueryExplainer: summary contains table names", "[query_explainer]") {
    // Test with schema-qualified table
    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    analysis.sub_type = "SELECT";
    analysis.source_tables.emplace_back("public", "sensitive_data");
    analysis.table_usage["public.sensitive_data"] = TableUsage::READ;

    ProjectionColumn p;
    p.name = "*";
    p.is_star_expansion = true;
    analysis.projections.push_back(std::move(p));
    analysis.is_star_select = true;

    auto explanation = QueryExplainer::explain(analysis);

    CHECK(explanation.summary.find("sensitive_data") != std::string::npos);
    CHECK(explanation.characteristics.has_star_select);
    CHECK(explanation.tables_read[0] == "public.sensitive_data");
}
