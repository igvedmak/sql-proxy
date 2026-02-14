#include <catch2/catch_test_macros.hpp>
#include "policy/policy_simulator.hpp"
#include <fstream>
#include <cstdio>

using namespace sqlproxy;

static Policy make_policy(const std::string& name, Decision action,
                           const std::string& table = "*",
                           const std::string& user = "*",
                           int priority = 10) {
    Policy p;
    p.name = name;
    p.action = action;
    p.scope.table = table;
    p.users.insert(user);
    p.priority = priority;
    return p;
}

static SimulationQuery make_query(const std::string& user,
                                   const std::string& sql,
                                   const std::string& table,
                                   Decision original_decision,
                                   const std::string& original_policy = "old-policy") {
    SimulationQuery q;
    q.user = user;
    q.database = "testdb";
    q.sql = sql;
    q.statement_type = StatementType::SELECT;
    q.source_tables.push_back(TableRef{table});
    q.original_decision = original_decision;
    q.original_policy = original_policy;
    return q;
}

TEST_CASE("PolicySimulator", "[policy_simulator]") {

    SECTION("No changes when policies match") {
        std::vector<Policy> policies = {
            make_policy("allow-all", Decision::ALLOW)
        };

        std::vector<SimulationQuery> queries = {
            make_query("alice", "SELECT * FROM users", "users", Decision::ALLOW)
        };

        auto result = PolicySimulator::simulate(policies, queries);
        REQUIRE(result.total_queries == 1);
        REQUIRE(result.unchanged == 1);
        REQUIRE(result.changed == 0);
        REQUIRE(result.diffs.empty());
    }

    SECTION("Detects newly blocked queries") {
        std::vector<Policy> policies = {
            make_policy("block-users", Decision::BLOCK, "users")
        };

        std::vector<SimulationQuery> queries = {
            make_query("alice", "SELECT * FROM users", "users", Decision::ALLOW)
        };

        auto result = PolicySimulator::simulate(policies, queries);
        REQUIRE(result.total_queries == 1);
        REQUIRE(result.changed == 1);
        REQUIRE(result.newly_blocked == 1);
        REQUIRE(result.newly_allowed == 0);
        REQUIRE(result.diffs.size() == 1);
        REQUIRE(result.diffs[0].original_decision == Decision::ALLOW);
        REQUIRE(result.diffs[0].new_decision == Decision::BLOCK);
    }

    SECTION("Detects newly allowed queries") {
        std::vector<Policy> policies = {
            make_policy("allow-all", Decision::ALLOW)
        };

        std::vector<SimulationQuery> queries = {
            make_query("alice", "SELECT * FROM secrets", "secrets", Decision::BLOCK)
        };

        auto result = PolicySimulator::simulate(policies, queries);
        REQUIRE(result.total_queries == 1);
        REQUIRE(result.changed == 1);
        REQUIRE(result.newly_allowed == 1);
        REQUIRE(result.newly_blocked == 0);
    }

    SECTION("Respects max_diffs limit") {
        std::vector<Policy> policies = {
            make_policy("block-all", Decision::BLOCK)
        };

        std::vector<SimulationQuery> queries;
        for (int i = 0; i < 10; i++) {
            queries.push_back(
                make_query("alice", "SELECT " + std::to_string(i),
                          "users", Decision::ALLOW));
        }

        auto result = PolicySimulator::simulate(policies, queries, 3);
        REQUIRE(result.total_queries == 10);
        REQUIRE(result.changed == 10);
        REQUIRE(result.diffs.size() == 3);
    }

    SECTION("Mixed results") {
        std::vector<Policy> policies = {
            make_policy("allow-users", Decision::ALLOW, "users", "*", 20),
            make_policy("block-secrets", Decision::BLOCK, "secrets", "*", 20)
        };

        std::vector<SimulationQuery> queries = {
            make_query("alice", "SELECT * FROM users", "users", Decision::ALLOW),
            make_query("bob", "SELECT * FROM secrets", "secrets", Decision::ALLOW),
            make_query("carol", "SELECT * FROM logs", "logs", Decision::BLOCK)
        };

        auto result = PolicySimulator::simulate(policies, queries);
        REQUIRE(result.total_queries == 3);
        // users: ALLOW -> ALLOW (unchanged)
        // secrets: ALLOW -> BLOCK (newly blocked)
        // logs: BLOCK -> default (depends on engine default)
        REQUIRE(result.changed >= 1);
    }

    SECTION("Empty queries returns zero results") {
        std::vector<Policy> policies = {make_policy("p1", Decision::ALLOW)};
        std::vector<SimulationQuery> queries;

        auto result = PolicySimulator::simulate(policies, queries);
        REQUIRE(result.total_queries == 0);
        REQUIRE(result.changed == 0);
        REQUIRE(result.unchanged == 0);
    }

    SECTION("Duration is tracked") {
        std::vector<Policy> policies = {make_policy("p1", Decision::ALLOW)};
        std::vector<SimulationQuery> queries = {
            make_query("alice", "SELECT 1", "t", Decision::ALLOW)
        };

        auto result = PolicySimulator::simulate(policies, queries);
        REQUIRE(result.duration.count() >= 0);
    }
}

TEST_CASE("PolicySimulator::parse_audit_line", "[policy_simulator]") {

    SECTION("Valid JSON line") {
        std::string line = R"({"user":"alice","database":"testdb","sql":"SELECT * FROM users","statement_type":"SELECT","decision":"ALLOW","matched_policy":"p1","tables":["users"]})";

        auto q = PolicySimulator::parse_audit_line(line);
        REQUIRE(q.has_value());
        REQUIRE(q->user == "alice");
        REQUIRE(q->database == "testdb");
        REQUIRE(q->sql == "SELECT * FROM users");
        REQUIRE(q->statement_type == StatementType::SELECT);
        REQUIRE(q->original_decision == Decision::ALLOW);
        REQUIRE(q->original_policy == "p1");
        REQUIRE(q->source_tables.size() == 1);
        REQUIRE(q->source_tables[0].table == "users");
    }

    SECTION("Missing required fields returns nullopt") {
        // Missing user
        std::string line1 = R"({"database":"testdb","sql":"SELECT 1","decision":"ALLOW"})";
        REQUIRE_FALSE(PolicySimulator::parse_audit_line(line1).has_value());

        // Missing sql
        std::string line2 = R"({"user":"alice","database":"testdb","decision":"ALLOW"})";
        REQUIRE_FALSE(PolicySimulator::parse_audit_line(line2).has_value());

        // Missing decision
        std::string line3 = R"({"user":"alice","database":"testdb","sql":"SELECT 1"})";
        REQUIRE_FALSE(PolicySimulator::parse_audit_line(line3).has_value());
    }

    SECTION("Default database when missing") {
        std::string line = R"({"user":"alice","sql":"SELECT 1","decision":"ALLOW"})";
        auto q = PolicySimulator::parse_audit_line(line);
        REQUIRE(q.has_value());
        REQUIRE(q->database == "default");
    }

    SECTION("Multiple tables") {
        std::string line = R"({"user":"alice","sql":"SELECT * FROM a JOIN b","decision":"ALLOW","tables":["a","b"]})";
        auto q = PolicySimulator::parse_audit_line(line);
        REQUIRE(q.has_value());
        REQUIRE(q->source_tables.size() == 2);
    }

    SECTION("Empty line returns nullopt") {
        REQUIRE_FALSE(PolicySimulator::parse_audit_line("").has_value());
    }
}

TEST_CASE("PolicySimulator::parse_audit_file", "[policy_simulator]") {

    SECTION("Reads JSONL file") {
        // Create temp file
        std::string path = "/tmp/test_audit_sim.jsonl";
        {
            std::ofstream f(path);
            f << R"({"user":"alice","sql":"SELECT 1","decision":"ALLOW"})" << "\n";
            f << R"({"user":"bob","sql":"SELECT 2","decision":"BLOCK"})" << "\n";
            f << "\n";  // empty line, should be skipped
            f << R"({"user":"carol","sql":"SELECT 3","decision":"ALLOW"})" << "\n";
        }

        auto queries = PolicySimulator::parse_audit_file(path);
        REQUIRE(queries.size() == 3);
        REQUIRE(queries[0].user == "alice");
        REQUIRE(queries[1].user == "bob");
        REQUIRE(queries[2].user == "carol");

        std::remove(path.c_str());
    }

    SECTION("Respects limit") {
        std::string path = "/tmp/test_audit_sim_limit.jsonl";
        {
            std::ofstream f(path);
            for (int i = 0; i < 10; i++) {
                f << R"({"user":"u)" << i << R"(","sql":"SELECT )" << i << R"(","decision":"ALLOW"})" << "\n";
            }
        }

        auto queries = PolicySimulator::parse_audit_file(path, 3);
        REQUIRE(queries.size() == 3);

        std::remove(path.c_str());
    }

    SECTION("Non-existent file returns empty") {
        auto queries = PolicySimulator::parse_audit_file("/tmp/no_such_file_12345.jsonl");
        REQUIRE(queries.empty());
    }
}

TEST_CASE("PolicySimulator::parse_policies_json", "[policy_simulator]") {

    SECTION("Parses policies array") {
        std::string json = R"({
            "policies": [
                {"name": "block-pii", "action": "BLOCK", "table": "customers", "users": ["alice", "bob"], "priority": 100},
                {"name": "allow-logs", "action": "ALLOW", "table": "logs", "priority": 50}
            ]
        })";

        auto policies = PolicySimulator::parse_policies_json(json);
        REQUIRE(policies.size() == 2);

        REQUIRE(policies[0].name == "block-pii");
        REQUIRE(policies[0].action == Decision::BLOCK);
        REQUIRE(policies[0].scope.table == "customers");
        REQUIRE(policies[0].priority == 100);
        REQUIRE(policies[0].users.contains("alice"));
        REQUIRE(policies[0].users.contains("bob"));

        REQUIRE(policies[1].name == "allow-logs");
        REQUIRE(policies[1].action == Decision::ALLOW);
        REQUIRE(policies[1].scope.table == "logs");
        REQUIRE(policies[1].priority == 50);
        REQUIRE(policies[1].users.contains("*"));  // Default
    }

    SECTION("Policy without name gets auto-name") {
        std::string json = R"({"policies": [{"action": "ALLOW"}]})";
        auto policies = PolicySimulator::parse_policies_json(json);
        REQUIRE(policies.size() == 1);
        REQUIRE(policies[0].name == "sim-policy-0");
    }

    SECTION("No policies array returns empty") {
        auto policies = PolicySimulator::parse_policies_json(R"({"foo": "bar"})");
        REQUIRE(policies.empty());
    }

    SECTION("Empty policies array returns empty") {
        auto policies = PolicySimulator::parse_policies_json(R"({"policies": []})");
        REQUIRE(policies.empty());
    }

    SECTION("Parses schema, database, columns, roles") {
        std::string json = R"({
            "policies": [
                {
                    "name": "p1",
                    "action": "BLOCK",
                    "schema": "private",
                    "database": "prod",
                    "columns": ["ssn", "salary"],
                    "roles": ["analyst"]
                }
            ]
        })";

        auto policies = PolicySimulator::parse_policies_json(json);
        REQUIRE(policies.size() == 1);
        REQUIRE(policies[0].scope.schema == "private");
        REQUIRE(policies[0].scope.database == "prod");
        REQUIRE(policies[0].scope.columns.size() == 2);
        REQUIRE(policies[0].roles.contains("analyst"));
    }
}
