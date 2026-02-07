#include <catch2/catch_test_macros.hpp>
#include "policy/policy_engine.hpp"
#include "analyzer/sql_analyzer.hpp"

using namespace sqlproxy;

// Helper: create AnalysisResult for a SELECT on a specific table
static AnalysisResult make_analysis(const std::string& table,
                                     const std::string& schema = "public") {
    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    analysis.sub_type = "SELECT";
    TableRef ref;
    ref.table = table;
    ref.schema = schema;
    analysis.source_tables.push_back(ref);
    analysis.table_usage[ref.full_name()] = TableUsage::READ;
    return analysis;
}

// Helper: create a column-level policy
static Policy make_column_policy(const std::string& name, Decision action,
                                  const std::string& table,
                                  const std::vector<std::string>& columns,
                                  const std::string& role,
                                  MaskingAction masking = MaskingAction::NONE) {
    Policy p;
    p.name = name;
    p.action = action;
    p.priority = 90;
    p.roles.insert(role);
    p.scope.database = "testdb";
    p.scope.schema = "public";
    p.scope.table = table;
    p.scope.columns = columns;
    p.masking_action = masking;
    return p;
}

// Helper: table-level ALLOW policy
static Policy make_table_allow(const std::string& name, const std::string& table,
                                const std::string& role) {
    Policy p;
    p.name = name;
    p.action = Decision::ALLOW;
    p.priority = 50;
    p.roles.insert(role);
    p.scope.database = "testdb";
    p.scope.schema = "public";
    p.scope.table = table;
    return p;
}

TEST_CASE("Column policy: no column policies returns all ALLOW", "[column_policy]") {
    PolicyEngine engine;

    // Only table-level policy
    Policy allow = make_table_allow("allow_customers", "customers", "analyst");
    engine.load_policies({allow});

    auto analysis = make_analysis("customers");
    std::vector<std::string> columns = {"id", "name", "email", "phone"};

    auto decisions = engine.evaluate_columns("analyst_user", {"analyst"}, "testdb",
                                              analysis, columns);

    REQUIRE(decisions.size() == 4);
    for (const auto& d : decisions) {
        CHECK(d.decision == Decision::ALLOW);
        CHECK(d.masking == MaskingAction::NONE);
    }
}

TEST_CASE("Column policy: BLOCK specific column", "[column_policy]") {
    PolicyEngine engine;

    Policy allow = make_table_allow("allow_sensitive", "sensitive_data", "analyst");
    Policy block_ssn = make_column_policy("block_ssn", Decision::BLOCK,
                                           "sensitive_data", {"ssn"}, "analyst");
    engine.load_policies({allow, block_ssn});

    auto analysis = make_analysis("sensitive_data");
    std::vector<std::string> columns = {"id", "name", "ssn", "salary"};

    auto decisions = engine.evaluate_columns("user1", {"analyst"}, "testdb",
                                              analysis, columns);

    REQUIRE(decisions.size() == 4);
    CHECK(decisions[0].decision == Decision::ALLOW);  // id
    CHECK(decisions[1].decision == Decision::ALLOW);  // name
    CHECK(decisions[2].decision == Decision::BLOCK);  // ssn - blocked
    CHECK(decisions[2].matched_policy == "block_ssn");
    CHECK(decisions[3].decision == Decision::ALLOW);  // salary
}

TEST_CASE("Column policy: ALLOW with masking", "[column_policy]") {
    PolicyEngine engine;

    Policy allow = make_table_allow("allow_customers", "customers", "developer");
    Policy mask_email = make_column_policy("mask_email", Decision::ALLOW,
                                            "customers", {"email"}, "developer",
                                            MaskingAction::PARTIAL);
    mask_email.masking_prefix_len = 3;
    mask_email.masking_suffix_len = 4;
    engine.load_policies({allow, mask_email});

    auto analysis = make_analysis("customers");
    std::vector<std::string> columns = {"id", "email", "name"};

    auto decisions = engine.evaluate_columns("dev1", {"developer"}, "testdb",
                                              analysis, columns);

    REQUIRE(decisions.size() == 3);
    CHECK(decisions[0].decision == Decision::ALLOW);
    CHECK(decisions[0].masking == MaskingAction::NONE);  // id - no masking

    CHECK(decisions[1].decision == Decision::ALLOW);
    CHECK(decisions[1].masking == MaskingAction::PARTIAL);  // email - masked
    CHECK(decisions[1].prefix_len == 3);
    CHECK(decisions[1].suffix_len == 4);
    CHECK(decisions[1].matched_policy == "mask_email");

    CHECK(decisions[2].decision == Decision::ALLOW);
    CHECK(decisions[2].masking == MaskingAction::NONE);  // name - no masking
}

TEST_CASE("Column policy: column wildcard * matches all", "[column_policy]") {
    PolicyEngine engine;

    Policy allow = make_table_allow("allow_sensitive", "sensitive_data", "readonly");
    Policy redact_all = make_column_policy("redact_all", Decision::ALLOW,
                                            "sensitive_data", {"*"}, "readonly",
                                            MaskingAction::REDACT);
    engine.load_policies({allow, redact_all});

    auto analysis = make_analysis("sensitive_data");
    std::vector<std::string> columns = {"id", "ssn", "salary"};

    auto decisions = engine.evaluate_columns("user1", {"readonly"}, "testdb",
                                              analysis, columns);

    REQUIRE(decisions.size() == 3);
    for (const auto& d : decisions) {
        CHECK(d.decision == Decision::ALLOW);
        CHECK(d.masking == MaskingAction::REDACT);
    }
}

TEST_CASE("Column policy: unmatched role gets no column policies", "[column_policy]") {
    PolicyEngine engine;

    Policy allow = make_table_allow("allow_customers", "customers", "admin");
    Policy block_ssn = make_column_policy("block_ssn", Decision::BLOCK,
                                           "customers", {"ssn"}, "analyst");
    engine.load_policies({allow, block_ssn});

    auto analysis = make_analysis("customers");
    std::vector<std::string> columns = {"id", "ssn"};

    // Admin user - block_ssn targets "analyst" role only
    auto decisions = engine.evaluate_columns("admin_user", {"admin"}, "testdb",
                                              analysis, columns);

    REQUIRE(decisions.size() == 2);
    CHECK(decisions[0].decision == Decision::ALLOW);
    CHECK(decisions[1].decision == Decision::ALLOW);  // ssn allowed for admin
}

TEST_CASE("Column policy: specificity - column beats table", "[column_policy]") {
    PolicyEngine engine;

    // Table-level BLOCK for analysts on sensitive_data
    Policy table_block;
    table_block.name = "block_sensitive";
    table_block.action = Decision::BLOCK;
    table_block.priority = 90;
    table_block.roles.insert("analyst");
    table_block.scope.database = "testdb";
    table_block.scope.table = "sensitive_data";

    // Column-level ALLOW with masking (higher specificity: 1000 + 100 > 100)
    Policy col_allow = make_column_policy("allow_salary_masked", Decision::ALLOW,
                                           "sensitive_data", {"salary"}, "analyst",
                                           MaskingAction::REDACT);
    engine.load_policies({table_block, col_allow});

    auto analysis = make_analysis("sensitive_data");
    std::vector<std::string> columns = {"salary"};

    auto decisions = engine.evaluate_columns("user1", {"analyst"}, "testdb",
                                              analysis, columns);

    REQUIRE(decisions.size() == 1);
    CHECK(decisions[0].decision == Decision::ALLOW);
    CHECK(decisions[0].masking == MaskingAction::REDACT);
    CHECK(decisions[0].matched_policy == "allow_salary_masked");
}
