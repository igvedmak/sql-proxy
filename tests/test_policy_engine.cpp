#include <catch2/catch_test_macros.hpp>
#include "policy/policy_engine.hpp"
#include "analyzer/sql_analyzer.hpp"

using namespace sqlproxy;

// Helper to create a simple AnalysisResult for policy testing
static AnalysisResult make_select_analysis(const std::string& table,
                                            const std::string& schema = "") {
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



static AnalysisResult make_multi_table_analysis(
    const std::vector<std::string>& tables) {
    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    analysis.sub_type = "SELECT";

    for (const auto& t : tables) {
        TableRef ref;
        ref.table = t;
        analysis.source_tables.push_back(ref);
        analysis.table_usage[ref.full_name()] = TableUsage::READ;
    }

    return analysis;
}

// Helper to build a policy for a specific table
static Policy make_policy(const std::string& name, Decision action,
                           const std::string& table = "",
                           const std::string& schema = "",
                           const std::string& database = "") {
    Policy p;
    p.name = name;
    p.action = action;
    p.priority = 0;
    p.users.insert("*");

    if (!table.empty()) p.scope.table = table;
    if (!schema.empty()) p.scope.schema = schema;
    if (!database.empty()) p.scope.database = database;

    return p;
}

TEST_CASE("PolicyEngine basic ALLOW and BLOCK", "[policy]") {

    PolicyEngine engine;

    SECTION("ALLOW policy permits access") {
        Policy allow = make_policy("allow_customers", Decision::ALLOW,
                                    "customers", "public");
        engine.load_policies({allow});

        auto analysis = make_select_analysis("customers", "public");
        auto result = engine.evaluate("alice", {}, "testdb", analysis);

        REQUIRE(result.decision == Decision::ALLOW);
    }

    SECTION("BLOCK policy denies access") {
        Policy block = make_policy("block_sensitive", Decision::BLOCK,
                                    "sensitive_data", "public");
        engine.load_policies({block});

        auto analysis = make_select_analysis("sensitive_data", "public");
        auto result = engine.evaluate("alice", {}, "testdb", analysis);

        REQUIRE(result.decision == Decision::BLOCK);
    }

    SECTION("Default DENY when no policies loaded") {
        engine.clear();

        auto analysis = make_select_analysis("customers");
        auto result = engine.evaluate("alice", {}, "testdb", analysis);

        REQUIRE(result.decision == Decision::BLOCK);
    }

    SECTION("Default DENY when no matching policies") {
        Policy allow = make_policy("allow_orders", Decision::ALLOW,
                                    "orders", "public");
        engine.load_policies({allow});

        // Query accesses 'customers', but only 'orders' policy exists
        auto analysis = make_select_analysis("customers");
        auto result = engine.evaluate("alice", {}, "testdb", analysis);

        REQUIRE(result.decision == Decision::BLOCK);
    }
}

TEST_CASE("PolicyEngine specificity resolution", "[policy]") {

    PolicyEngine engine;

    SECTION("Table-level policy beats schema-level") {
        // Schema-level ALLOW (specificity=10)
        Policy schema_allow = make_policy("schema_allow", Decision::ALLOW,
                                           "", "public");
        schema_allow.scope.table = std::nullopt;  // Clear table scope

        // Table-level BLOCK (specificity=110)
        Policy table_block = make_policy("table_block", Decision::BLOCK,
                                          "sensitive_data", "public");

        engine.load_policies({schema_allow, table_block});

        auto analysis = make_select_analysis("sensitive_data", "public");
        auto result = engine.evaluate("alice", {}, "testdb", analysis);

        // Table-level specificity (110) > Schema-level (10), so BLOCK wins
        REQUIRE(result.decision == Decision::BLOCK);
        REQUIRE(result.matched_policy == "table_block");
    }

    SECTION("Schema-level policy beats database-level") {
        // Database-level ALLOW (specificity=1)
        Policy db_allow;
        db_allow.name = "db_allow";
        db_allow.action = Decision::ALLOW;
        db_allow.users.insert("*");
        db_allow.scope.database = "mydb";

        // Schema-level BLOCK (specificity=11)
        Policy schema_block;
        schema_block.name = "schema_block";
        schema_block.action = Decision::BLOCK;
        schema_block.users.insert("*");
        schema_block.scope.database = "mydb";
        schema_block.scope.schema = "secret";

        engine.load_policies({db_allow, schema_block});

        auto analysis = make_select_analysis("customers", "secret");
        auto result = engine.evaluate("alice", {}, "testdb", analysis);

        REQUIRE(result.decision == Decision::BLOCK);
    }

    SECTION("BLOCK wins over ALLOW at same specificity") {
        // Two table-level policies for same table, one ALLOW one BLOCK
        Policy allow = make_policy("allow_customers", Decision::ALLOW,
                                    "customers", "public");
        Policy block = make_policy("block_customers", Decision::BLOCK,
                                    "customers", "public");

        engine.load_policies({allow, block});

        auto analysis = make_select_analysis("customers", "public");
        auto result = engine.evaluate("alice", {}, "testdb", analysis);

        // At same specificity, BLOCK wins
        REQUIRE(result.decision == Decision::BLOCK);
    }
}

TEST_CASE("PolicyEngine multi-table evaluation", "[policy]") {

    PolicyEngine engine;

    SECTION("ANY blocked table blocks entire query") {
        Policy allow_customers = make_policy("allow_customers", Decision::ALLOW,
                                              "customers", "public");
        Policy block_sensitive = make_policy("block_sensitive", Decision::BLOCK,
                                              "sensitive_data", "public");

        engine.load_policies({allow_customers, block_sensitive});

        // Query accesses both customers and sensitive_data
        auto analysis = make_multi_table_analysis({"customers", "sensitive_data"});
        auto result = engine.evaluate("alice", {}, "testdb", analysis);

        REQUIRE(result.decision == Decision::BLOCK);
    }

    SECTION("All tables allowed when all have ALLOW policies") {
        Policy allow_customers = make_policy("allow_customers", Decision::ALLOW,
                                              "customers", "public");
        Policy allow_orders = make_policy("allow_orders", Decision::ALLOW,
                                           "orders", "public");

        engine.load_policies({allow_customers, allow_orders});

        auto analysis = make_multi_table_analysis({"customers", "orders"});
        auto result = engine.evaluate("alice", {}, "testdb", analysis);

        REQUIRE(result.decision == Decision::ALLOW);
    }

    SECTION("Missing policy for any table blocks query") {
        Policy allow_customers = make_policy("allow_customers", Decision::ALLOW,
                                              "customers", "public");
        engine.load_policies({allow_customers});

        // orders has no policy -> default deny
        auto analysis = make_multi_table_analysis({"customers", "orders"});
        auto result = engine.evaluate("alice", {}, "testdb", analysis);

        REQUIRE(result.decision == Decision::BLOCK);
    }
}

TEST_CASE("PolicyEngine user matching", "[policy]") {

    PolicyEngine engine;

    SECTION("User-specific policy matches only that user") {
        Policy alice_allow;
        alice_allow.name = "alice_allow";
        alice_allow.action = Decision::ALLOW;
        alice_allow.users.insert("alice");
        alice_allow.scope.table = "customers";
        alice_allow.scope.schema = "public";

        engine.load_policies({alice_allow});

        auto analysis = make_select_analysis("customers", "public");

        // Alice should be allowed
        auto result_alice = engine.evaluate("alice", {}, "testdb", analysis);
        REQUIRE(result_alice.decision == Decision::ALLOW);

        // Bob should be blocked (no matching policy)
        auto result_bob = engine.evaluate("bob", {}, "testdb", analysis);
        REQUIRE(result_bob.decision == Decision::BLOCK);
    }

    SECTION("Wildcard user policy matches everyone") {
        Policy allow_all = make_policy("allow_all", Decision::ALLOW,
                                        "customers", "public");
        // make_policy already inserts "*" as user
        engine.load_policies({allow_all});

        auto analysis = make_select_analysis("customers", "public");

        REQUIRE(engine.evaluate("alice", {}, "testdb", analysis).decision == Decision::ALLOW);
        REQUIRE(engine.evaluate("bob", {}, "testdb", analysis).decision == Decision::ALLOW);
        REQUIRE(engine.evaluate("charlie", {}, "testdb", analysis).decision == Decision::ALLOW);
    }
}

TEST_CASE("PolicyEngine role matching", "[policy]") {

    PolicyEngine engine;

    SECTION("Role-based policy matches users with that role") {
        Policy analyst_allow;
        analyst_allow.name = "analyst_allow";
        analyst_allow.action = Decision::ALLOW;
        analyst_allow.roles.insert("analyst");
        analyst_allow.scope.table = "customers";
        analyst_allow.scope.schema = "public";

        engine.load_policies({analyst_allow});

        auto analysis = make_select_analysis("customers", "public");

        // User with analyst role should be allowed
        auto result = engine.evaluate("alice", {"analyst"}, "testdb", analysis);
        REQUIRE(result.decision == Decision::ALLOW);

        // User without analyst role should be blocked
        auto result2 = engine.evaluate("bob", {"developer"}, "testdb", analysis);
        REQUIRE(result2.decision == Decision::BLOCK);
    }

    SECTION("Multiple roles - any matching role grants access") {
        Policy admin_allow;
        admin_allow.name = "admin_allow";
        admin_allow.action = Decision::ALLOW;
        admin_allow.roles.insert("admin");
        admin_allow.scope.table = "sensitive_data";
        admin_allow.scope.schema = "public";

        engine.load_policies({admin_allow});

        auto analysis = make_select_analysis("sensitive_data", "public");

        // User with admin among their roles should match
        auto result = engine.evaluate("alice", {"developer", "admin"}, "testdb", analysis);
        REQUIRE(result.decision == Decision::ALLOW);
    }
}

TEST_CASE("PolicyEngine exclude_roles precedence", "[policy]") {

    PolicyEngine engine;

    SECTION("Excluded role prevents policy from matching") {
        Policy allow_all;
        allow_all.name = "allow_all_except_interns";
        allow_all.action = Decision::ALLOW;
        allow_all.users.insert("*");
        allow_all.exclude_roles.insert("intern");
        allow_all.scope.table = "customers";
        allow_all.scope.schema = "public";

        engine.load_policies({allow_all});

        auto analysis = make_select_analysis("customers", "public");

        // Regular user should be allowed
        auto result1 = engine.evaluate("alice", {"developer"}, "testdb", analysis);
        REQUIRE(result1.decision == Decision::ALLOW);

        // User with excluded role should be blocked (policy doesn't match them)
        auto result2 = engine.evaluate("bob", {"intern"}, "testdb", analysis);
        REQUIRE(result2.decision == Decision::BLOCK);
    }

    SECTION("Exclude role overrides user match") {
        Policy allow_alice;
        allow_alice.name = "allow_alice";
        allow_alice.action = Decision::ALLOW;
        allow_alice.users.insert("alice");
        allow_alice.exclude_roles.insert("suspended");
        allow_alice.scope.table = "customers";
        allow_alice.scope.schema = "public";

        engine.load_policies({allow_alice});

        auto analysis = make_select_analysis("customers", "public");

        // Alice normally allowed
        auto result1 = engine.evaluate("alice", {}, "testdb", analysis);
        REQUIRE(result1.decision == Decision::ALLOW);

        // Alice with suspended role should be blocked
        auto result2 = engine.evaluate("alice", {"suspended"}, "testdb", analysis);
        REQUIRE(result2.decision == Decision::BLOCK);
    }
}

TEST_CASE("PolicyEngine utility statements", "[policy]") {

    PolicyEngine engine;

    SECTION("Utility statements with no tables are allowed") {
        engine.load_policies({}); // No policies

        AnalysisResult analysis;
        analysis.statement_type = StatementType::SET;
        // No tables

        auto result = engine.evaluate("alice", {}, "testdb", analysis);
        REQUIRE(result.decision == Decision::ALLOW);
    }
}

TEST_CASE("PolicyEngine reload and clear", "[policy]") {

    PolicyEngine engine;

    SECTION("Reload replaces policies") {
        Policy allow = make_policy("allow_customers", Decision::ALLOW,
                                    "customers", "public");
        engine.load_policies({allow});

        auto analysis = make_select_analysis("customers", "public");
        REQUIRE(engine.evaluate("alice", {}, "testdb", analysis).decision == Decision::ALLOW);

        // Reload with blocking policy
        Policy block = make_policy("block_customers", Decision::BLOCK,
                                    "customers", "public");
        engine.reload_policies({block});

        REQUIRE(engine.evaluate("alice", {}, "testdb", analysis).decision == Decision::BLOCK);
    }

    SECTION("Clear removes all policies") {
        Policy allow = make_policy("allow_customers", Decision::ALLOW,
                                    "customers", "public");
        engine.load_policies({allow});

        engine.clear();
        REQUIRE(engine.policy_count() == 0);

        auto analysis = make_select_analysis("customers", "public");
        REQUIRE(engine.evaluate("alice", {}, "testdb", analysis).decision == Decision::BLOCK);
    }
}

TEST_CASE("PolicyScope specificity scoring", "[policy]") {

    SECTION("No scope = specificity 0") {
        PolicyScope scope;
        REQUIRE(scope.specificity() == 0);
    }

    SECTION("Database only = specificity 1") {
        PolicyScope scope;
        scope.database = "mydb";
        REQUIRE(scope.specificity() == 1);
    }

    SECTION("Schema only = specificity 10") {
        PolicyScope scope;
        scope.schema = "public";
        REQUIRE(scope.specificity() == 10);
    }

    SECTION("Table only = specificity 100") {
        PolicyScope scope;
        scope.table = "users";
        REQUIRE(scope.specificity() == 100);
    }

    SECTION("Database + schema = specificity 11") {
        PolicyScope scope;
        scope.database = "mydb";
        scope.schema = "public";
        REQUIRE(scope.specificity() == 11);
    }

    SECTION("Database + schema + table = specificity 111") {
        PolicyScope scope;
        scope.database = "mydb";
        scope.schema = "public";
        scope.table = "users";
        REQUIRE(scope.specificity() == 111);
    }

    SECTION("Schema + table = specificity 110") {
        PolicyScope scope;
        scope.schema = "public";
        scope.table = "users";
        REQUIRE(scope.specificity() == 110);
    }
}
