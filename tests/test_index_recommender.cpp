#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>
#include "analyzer/index_recommender.hpp"
#include "analyzer/sql_analyzer.hpp"

using namespace sqlproxy;

// Helper to create an AnalysisResult with source_tables and filter_columns
static AnalysisResult make_analysis(const std::string& table,
                                     const std::vector<std::string>& filter_cols) {
    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    analysis.sub_type = "SELECT";

    TableRef ref;
    ref.table = table;
    analysis.source_tables.push_back(ref);

    for (const auto& col : filter_cols) {
        analysis.filter_columns.emplace_back(col);
    }

    return analysis;
}

TEST_CASE("IndexRecommender: empty when no patterns recorded", "[index_recommender]") {
    IndexRecommender::Config cfg;
    cfg.enabled = true;
    cfg.min_occurrences = 3;
    IndexRecommender recommender(cfg);

    auto recs = recommender.get_recommendations();
    REQUIRE(recs.empty());
}

TEST_CASE("IndexRecommender: respects min_occurrences threshold", "[index_recommender]") {
    IndexRecommender::Config cfg;
    cfg.enabled = true;
    cfg.min_occurrences = 3;
    IndexRecommender recommender(cfg);

    auto analysis = make_analysis("customers", {"email"});

    // Record only 2 times (below threshold of 3)
    recommender.record(analysis, 12345, std::chrono::microseconds(100));
    recommender.record(analysis, 12345, std::chrono::microseconds(200));

    auto recs = recommender.get_recommendations();
    REQUIRE(recs.empty());

    // Record a 3rd time (meets threshold)
    recommender.record(analysis, 12345, std::chrono::microseconds(300));

    recs = recommender.get_recommendations();
    REQUIRE(recs.size() == 1);
    REQUIRE(recs[0].table == "customers");
    REQUIRE(recs[0].occurrence_count == 3);
}

TEST_CASE("IndexRecommender: records filter patterns and generates recommendations", "[index_recommender]") {
    IndexRecommender::Config cfg;
    cfg.enabled = true;
    cfg.min_occurrences = 2;
    IndexRecommender recommender(cfg);

    auto analysis = make_analysis("orders", {"status", "customer_id"});

    recommender.record(analysis, 11111, std::chrono::microseconds(500));
    recommender.record(analysis, 11111, std::chrono::microseconds(700));
    recommender.record(analysis, 11111, std::chrono::microseconds(600));

    auto recs = recommender.get_recommendations();
    REQUIRE(recs.size() == 1);
    REQUIRE(recs[0].table == "orders");
    REQUIRE(recs[0].occurrence_count == 3);

    // Columns should be sorted alphabetically
    REQUIRE(recs[0].columns.size() == 2);
    REQUIRE(recs[0].columns[0] == "customer_id");
    REQUIRE(recs[0].columns[1] == "status");

    // Average execution time: (500+700+600)/3 = 600
    REQUIRE(recs[0].avg_execution_time_us == Catch::Approx(600.0));
}

TEST_CASE("IndexRecommender: suggested DDL is correct format", "[index_recommender]") {
    IndexRecommender::Config cfg;
    cfg.enabled = true;
    cfg.min_occurrences = 1;
    IndexRecommender recommender(cfg);

    auto analysis = make_analysis("users", {"email", "name"});
    recommender.record(analysis, 99999, std::chrono::microseconds(100));

    auto recs = recommender.get_recommendations();
    REQUIRE(recs.size() == 1);

    // Columns sorted: email, name
    REQUIRE(recs[0].suggested_ddl == "CREATE INDEX idx_users_email_name ON users(email, name)");
}

TEST_CASE("IndexRecommender: single column DDL format", "[index_recommender]") {
    IndexRecommender::Config cfg;
    cfg.enabled = true;
    cfg.min_occurrences = 1;
    IndexRecommender recommender(cfg);

    auto analysis = make_analysis("products", {"price"});
    recommender.record(analysis, 88888, std::chrono::microseconds(50));

    auto recs = recommender.get_recommendations();
    REQUIRE(recs.size() == 1);
    REQUIRE(recs[0].suggested_ddl == "CREATE INDEX idx_products_price ON products(price)");
}

TEST_CASE("IndexRecommender: disabled recommender does not record", "[index_recommender]") {
    IndexRecommender::Config cfg;
    cfg.enabled = false;
    IndexRecommender recommender(cfg);

    auto analysis = make_analysis("customers", {"email"});
    recommender.record(analysis, 12345, std::chrono::microseconds(100));
    recommender.record(analysis, 12345, std::chrono::microseconds(100));
    recommender.record(analysis, 12345, std::chrono::microseconds(100));

    auto recs = recommender.get_recommendations();
    REQUIRE(recs.empty());
}

TEST_CASE("IndexRecommender: sorts by occurrence_count descending", "[index_recommender]") {
    IndexRecommender::Config cfg;
    cfg.enabled = true;
    cfg.min_occurrences = 1;
    IndexRecommender recommender(cfg);

    auto analysis_a = make_analysis("table_a", {"col_a"});
    auto analysis_b = make_analysis("table_b", {"col_b"});

    // table_a: 2 occurrences
    recommender.record(analysis_a, 1, std::chrono::microseconds(100));
    recommender.record(analysis_a, 1, std::chrono::microseconds(100));

    // table_b: 5 occurrences
    for (int i = 0; i < 5; ++i) {
        recommender.record(analysis_b, 2, std::chrono::microseconds(100));
    }

    auto recs = recommender.get_recommendations();
    REQUIRE(recs.size() == 2);
    REQUIRE(recs[0].table == "table_b");
    REQUIRE(recs[0].occurrence_count == 5);
    REQUIRE(recs[1].table == "table_a");
    REQUIRE(recs[1].occurrence_count == 2);
}

TEST_CASE("IndexRecommender: respects max_recommendations limit", "[index_recommender]") {
    IndexRecommender::Config cfg;
    cfg.enabled = true;
    cfg.min_occurrences = 1;
    cfg.max_recommendations = 2;
    IndexRecommender recommender(cfg);

    // Create 5 different patterns
    for (int i = 0; i < 5; ++i) {
        auto analysis = make_analysis("table_" + std::to_string(i), {"col"});
        recommender.record(analysis, static_cast<uint64_t>(i), std::chrono::microseconds(100));
    }

    auto recs = recommender.get_recommendations();
    REQUIRE(recs.size() == 2);
}

TEST_CASE("IndexRecommender: is_enabled reflects config", "[index_recommender]") {
    IndexRecommender::Config cfg_on;
    cfg_on.enabled = true;
    IndexRecommender on(cfg_on);
    REQUIRE(on.is_enabled());

    IndexRecommender::Config cfg_off;
    cfg_off.enabled = false;
    IndexRecommender off(cfg_off);
    REQUIRE_FALSE(off.is_enabled());
}
