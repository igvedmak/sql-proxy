#include <catch2/catch_test_macros.hpp>
#include "core/query_rewriter.hpp"

using namespace sqlproxy;

// Helper: create AnalysisResult for a SELECT on a specific table
static AnalysisResult make_select(const std::string& table) {
    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    analysis.sub_type = "SELECT";
    TableRef ref;
    ref.table = table;
    analysis.source_tables.push_back(ref);
    analysis.table_usage[ref.full_name()] = TableUsage::READ;
    return analysis;
}

// ============================================================================
// Enforce Limit
// ============================================================================

TEST_CASE("QueryRewriter: enforce_limit adds LIMIT to query without one", "[rewriter]") {
    QueryRewriter rewriter;

    RewriteRule rule;
    rule.name = "enforce_limit";
    rule.type = "enforce_limit";
    rule.limit_value = 1000;
    rewriter.load_rules({}, {rule});

    auto analysis = make_select("customers");
    auto result = rewriter.rewrite(
        "SELECT * FROM customers", "user1", {}, "testdb", analysis, {});

    REQUIRE(!result.empty());
    CHECK(result == "SELECT * FROM customers LIMIT 1000");
}

TEST_CASE("QueryRewriter: enforce_limit skips query with existing LIMIT", "[rewriter]") {
    QueryRewriter rewriter;

    RewriteRule rule;
    rule.name = "enforce_limit";
    rule.type = "enforce_limit";
    rule.limit_value = 1000;
    rewriter.load_rules({}, {rule});

    auto analysis = make_select("customers");
    auto result = rewriter.rewrite(
        "SELECT * FROM customers LIMIT 50", "user1", {}, "testdb", analysis, {});

    CHECK(result.empty());  // No rewrite needed
}

TEST_CASE("QueryRewriter: enforce_limit handles semicolons", "[rewriter]") {
    QueryRewriter rewriter;

    RewriteRule rule;
    rule.name = "enforce_limit";
    rule.type = "enforce_limit";
    rule.limit_value = 500;
    rewriter.load_rules({}, {rule});

    auto analysis = make_select("orders");
    auto result = rewriter.rewrite(
        "SELECT * FROM orders;", "user1", {}, "testdb", analysis, {});

    REQUIRE(!result.empty());
    CHECK(result == "SELECT * FROM orders LIMIT 500;");
}

TEST_CASE("QueryRewriter: enforce_limit respects role filter", "[rewriter]") {
    QueryRewriter rewriter;

    RewriteRule rule;
    rule.name = "enforce_limit";
    rule.type = "enforce_limit";
    rule.limit_value = 100;
    rule.roles = {"analyst"};
    rewriter.load_rules({}, {rule});

    auto analysis = make_select("customers");

    // Analyst → rewrite applied
    auto result = rewriter.rewrite(
        "SELECT * FROM customers", "user1", {"analyst"}, "testdb", analysis, {});
    CHECK(!result.empty());

    // Admin → no rewrite
    result = rewriter.rewrite(
        "SELECT * FROM customers", "admin", {"admin"}, "testdb", analysis, {});
    CHECK(result.empty());
}

// ============================================================================
// Row-Level Security (RLS)
// ============================================================================

TEST_CASE("QueryRewriter: RLS injects WHERE clause", "[rewriter]") {
    QueryRewriter rewriter;

    RlsRule rule;
    rule.name = "region_filter";
    rule.database = "testdb";
    rule.table = "customers";
    rule.condition = "region = '$ATTR.region'";
    rule.roles = {"analyst"};
    rewriter.load_rules({rule}, {});

    auto analysis = make_select("customers");
    std::unordered_map<std::string, std::string> attrs = {{"region", "us-west"}};

    auto result = rewriter.rewrite(
        "SELECT * FROM customers", "user1", {"analyst"}, "testdb", analysis, attrs);

    REQUIRE(!result.empty());
    CHECK(result == "SELECT * FROM customers WHERE (region = 'us-west')");
}

TEST_CASE("QueryRewriter: RLS appends AND to existing WHERE", "[rewriter]") {
    QueryRewriter rewriter;

    RlsRule rule;
    rule.name = "region_filter";
    rule.database = "testdb";
    rule.table = "customers";
    rule.condition = "region = '$ATTR.region'";
    rule.roles = {"analyst"};
    rewriter.load_rules({rule}, {});

    auto analysis = make_select("customers");
    std::unordered_map<std::string, std::string> attrs = {{"region", "eu"}};

    auto result = rewriter.rewrite(
        "SELECT * FROM customers WHERE active = true", "user1", {"analyst"}, "testdb", analysis, attrs);

    REQUIRE(!result.empty());
    CHECK(result == "SELECT * FROM customers WHERE (region = 'eu') AND active = true");
}

TEST_CASE("QueryRewriter: RLS $USER expansion", "[rewriter]") {
    QueryRewriter rewriter;

    RlsRule rule;
    rule.name = "owner_filter";
    rule.database = "testdb";
    rule.table = "orders";
    rule.condition = "created_by = '$USER'";
    rewriter.load_rules({rule}, {});

    auto analysis = make_select("orders");

    auto result = rewriter.rewrite(
        "SELECT * FROM orders", "alice", {}, "testdb", analysis, {});

    REQUIRE(!result.empty());
    CHECK(result == "SELECT * FROM orders WHERE (created_by = 'alice')");
}

TEST_CASE("QueryRewriter: RLS $ROLES expansion", "[rewriter]") {
    QueryRewriter rewriter;

    RlsRule rule;
    rule.name = "role_filter";
    rule.database = "testdb";
    rule.table = "data";
    rule.condition = "access_role IN ($ROLES)";
    rewriter.load_rules({rule}, {});

    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    TableRef ref;
    ref.table = "data";
    analysis.source_tables.push_back(ref);

    auto result = rewriter.rewrite(
        "SELECT * FROM data", "user1", {"analyst", "readonly"}, "testdb", analysis, {});

    REQUIRE(!result.empty());
    CHECK(result == "SELECT * FROM data WHERE (access_role IN ('analyst','readonly'))");
}

TEST_CASE("QueryRewriter: RLS skips unmatched database", "[rewriter]") {
    QueryRewriter rewriter;

    RlsRule rule;
    rule.name = "region_filter";
    rule.database = "production";  // Different database
    rule.table = "customers";
    rule.condition = "region = 'us'";
    rewriter.load_rules({rule}, {});

    auto analysis = make_select("customers");

    auto result = rewriter.rewrite(
        "SELECT * FROM customers", "user1", {}, "testdb", analysis, {});

    CHECK(result.empty());  // Not applied - wrong database
}

TEST_CASE("QueryRewriter: RLS skips unmatched table", "[rewriter]") {
    QueryRewriter rewriter;

    RlsRule rule;
    rule.name = "region_filter";
    rule.database = "testdb";
    rule.table = "orders";  // Different table
    rule.condition = "region = 'us'";
    rewriter.load_rules({rule}, {});

    auto analysis = make_select("customers");

    auto result = rewriter.rewrite(
        "SELECT * FROM customers", "user1", {}, "testdb", analysis, {});

    CHECK(result.empty());  // Not applied - wrong table
}

TEST_CASE("QueryRewriter: combined RLS + enforce_limit", "[rewriter]") {
    QueryRewriter rewriter;

    RlsRule rls;
    rls.name = "region_filter";
    rls.database = "testdb";
    rls.table = "customers";
    rls.condition = "region = '$ATTR.region'";

    RewriteRule limit;
    limit.name = "enforce_limit";
    limit.type = "enforce_limit";
    limit.limit_value = 100;

    rewriter.load_rules({rls}, {limit});

    auto analysis = make_select("customers");
    std::unordered_map<std::string, std::string> attrs = {{"region", "us-west"}};

    auto result = rewriter.rewrite(
        "SELECT * FROM customers", "user1", {}, "testdb", analysis, attrs);

    REQUIRE(!result.empty());
    // Should have both WHERE and LIMIT
    CHECK(result.find("WHERE (region = 'us-west')") != std::string::npos);
    CHECK(result.find("LIMIT 100") != std::string::npos);
}

TEST_CASE("QueryRewriter: hot reload rules", "[rewriter]") {
    QueryRewriter rewriter;

    // Initial: no rules
    rewriter.load_rules({}, {});
    auto analysis = make_select("customers");
    auto result = rewriter.rewrite("SELECT * FROM customers", "u", {}, "db", analysis, {});
    CHECK(result.empty());

    // Reload with enforce_limit
    RewriteRule rule;
    rule.name = "enforce_limit";
    rule.type = "enforce_limit";
    rule.limit_value = 50;
    rewriter.reload_rules({}, {rule});

    result = rewriter.rewrite("SELECT * FROM customers", "u", {}, "db", analysis, {});
    CHECK(!result.empty());
    CHECK(result.find("LIMIT 50") != std::string::npos);
}

TEST_CASE("QueryRewriter: INSERT not rewritten", "[rewriter]") {
    QueryRewriter rewriter;

    RewriteRule rule;
    rule.name = "enforce_limit";
    rule.type = "enforce_limit";
    rule.limit_value = 100;
    rewriter.load_rules({}, {rule});

    AnalysisResult analysis;
    analysis.statement_type = StatementType::INSERT;
    TableRef ref;
    ref.table = "customers";
    analysis.target_tables.push_back(ref);

    auto result = rewriter.rewrite(
        "INSERT INTO customers VALUES (1, 'Alice')", "u", {}, "db", analysis, {});

    CHECK(result.empty());  // Not a SELECT → no rewrite
}
