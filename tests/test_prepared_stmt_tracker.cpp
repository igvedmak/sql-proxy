#include <catch2/catch_test_macros.hpp>
#include "server/prepared_stmt_tracker.hpp"

using namespace sqlproxy;

TEST_CASE("PreparedStatementTracker: register and find", "[prepared]") {
    PreparedStatementTracker tracker;

    PreparedStatementEntry entry;
    entry.name = "my_query";
    entry.original_sql = "SELECT * FROM customers WHERE id = $1";

    tracker.register_statement("alice", "my_query", entry);

    auto found = tracker.find_statement("alice", "my_query");
    REQUIRE(found.has_value());
    CHECK(found->name == "my_query");
    CHECK(found->original_sql == "SELECT * FROM customers WHERE id = $1");
}

TEST_CASE("PreparedStatementTracker: not found returns nullopt", "[prepared]") {
    PreparedStatementTracker tracker;
    CHECK_FALSE(tracker.find_statement("alice", "nonexistent").has_value());
}

TEST_CASE("PreparedStatementTracker: unknown user returns nullopt", "[prepared]") {
    PreparedStatementTracker tracker;

    PreparedStatementEntry entry;
    entry.name = "my_query";
    tracker.register_statement("alice", "my_query", entry);

    CHECK_FALSE(tracker.find_statement("bob", "my_query").has_value());
}

TEST_CASE("PreparedStatementTracker: deallocate_statement", "[prepared]") {
    PreparedStatementTracker tracker;

    PreparedStatementEntry entry;
    entry.name = "my_query";
    tracker.register_statement("alice", "my_query", entry);

    tracker.deallocate_statement("alice", "my_query");
    CHECK_FALSE(tracker.find_statement("alice", "my_query").has_value());
}

TEST_CASE("PreparedStatementTracker: deallocate_all", "[prepared]") {
    PreparedStatementTracker tracker;

    PreparedStatementEntry e1, e2;
    e1.name = "q1";
    e2.name = "q2";
    tracker.register_statement("alice", "q1", e1);
    tracker.register_statement("alice", "q2", e2);

    CHECK(tracker.total_statements() == 2);

    tracker.deallocate_all("alice");
    CHECK(tracker.total_statements() == 0);
    CHECK_FALSE(tracker.find_statement("alice", "q1").has_value());
}

TEST_CASE("PreparedStatementTracker: user isolation", "[prepared]") {
    PreparedStatementTracker tracker;

    PreparedStatementEntry e1, e2;
    e1.name = "same_name";
    e1.original_sql = "SELECT 1";
    e2.name = "same_name";
    e2.original_sql = "SELECT 2";

    tracker.register_statement("alice", "same_name", e1);
    tracker.register_statement("bob", "same_name", e2);

    auto alice_stmt = tracker.find_statement("alice", "same_name");
    auto bob_stmt = tracker.find_statement("bob", "same_name");

    REQUIRE(alice_stmt.has_value());
    REQUIRE(bob_stmt.has_value());
    CHECK(alice_stmt->original_sql == "SELECT 1");
    CHECK(bob_stmt->original_sql == "SELECT 2");
}

TEST_CASE("PreparedStatementTracker: total_statements", "[prepared]") {
    PreparedStatementTracker tracker;
    CHECK(tracker.total_statements() == 0);

    PreparedStatementEntry e;
    e.name = "q1";
    tracker.register_statement("alice", "q1", e);
    CHECK(tracker.total_statements() == 1);

    e.name = "q2";
    tracker.register_statement("alice", "q2", e);
    CHECK(tracker.total_statements() == 2);

    e.name = "q1";
    tracker.register_statement("bob", "q1", e);
    CHECK(tracker.total_statements() == 3);
}

TEST_CASE("PreparedStatementTracker: overwrite existing statement", "[prepared]") {
    PreparedStatementTracker tracker;

    PreparedStatementEntry e1;
    e1.name = "my_query";
    e1.original_sql = "SELECT 1";
    tracker.register_statement("alice", "my_query", e1);

    PreparedStatementEntry e2;
    e2.name = "my_query";
    e2.original_sql = "SELECT 2";
    tracker.register_statement("alice", "my_query", e2);

    auto found = tracker.find_statement("alice", "my_query");
    REQUIRE(found.has_value());
    CHECK(found->original_sql == "SELECT 2");
    CHECK(tracker.total_statements() == 1);  // Not duplicated
}
