#include <catch2/catch_test_macros.hpp>
#include "schema/schema_manager.hpp"

using namespace sqlproxy;

TEST_CASE("SchemaManager: basic construction", "[schema]") {
    SchemaManagementConfig config;
    config.enabled = true;
    config.require_approval = false;
    config.max_history_entries = 100;

    SchemaManager mgr(config);
    REQUIRE(mgr.history_size() == 0);
    REQUIRE(mgr.pending_count() == 0);
}

TEST_CASE("SchemaManager: record DDL change", "[schema]") {
    SchemaManagementConfig config;
    config.enabled = true;

    SchemaManager mgr(config);

    mgr.record_change("admin", "testdb", "users",
        "CREATE TABLE users (id INT)", StatementType::CREATE_TABLE);

    REQUIRE(mgr.history_size() == 1);

    auto history = mgr.get_history();
    REQUIRE(history.size() == 1);
    REQUIRE(history[0].user == "admin");
    REQUIRE(history[0].database == "testdb");
    REQUIRE(history[0].table == "users");
    REQUIRE(history[0].status == "applied");
}

TEST_CASE("SchemaManager: disabled does not record", "[schema]") {
    SchemaManagementConfig config;
    config.enabled = false;

    SchemaManager mgr(config);

    mgr.record_change("admin", "testdb", "users",
        "CREATE TABLE users (id INT)", StatementType::CREATE_TABLE);

    REQUIRE(mgr.history_size() == 0);
}

TEST_CASE("SchemaManager: intercept DDL without approval required", "[schema]") {
    SchemaManagementConfig config;
    config.enabled = true;
    config.require_approval = false;

    SchemaManager mgr(config);

    // Should allow DDL when approval not required
    bool allowed = mgr.intercept_ddl("admin", "testdb",
        "CREATE TABLE test (id INT)", StatementType::CREATE_TABLE);
    REQUIRE(allowed == true);
    REQUIRE(mgr.pending_count() == 0);
}

TEST_CASE("SchemaManager: intercept DDL with approval required", "[schema]") {
    SchemaManagementConfig config;
    config.enabled = true;
    config.require_approval = true;

    SchemaManager mgr(config);

    // Should block DDL when approval required
    bool allowed = mgr.intercept_ddl("dev", "testdb",
        "CREATE TABLE test (id INT)", StatementType::CREATE_TABLE);
    REQUIRE(allowed == false);
    REQUIRE(mgr.pending_count() == 1);

    auto pending = mgr.get_pending();
    REQUIRE(pending.size() == 1);
    REQUIRE(pending[0].user == "dev");
    REQUIRE(pending[0].database == "testdb");
    REQUIRE(pending[0].status == "pending");
}

TEST_CASE("SchemaManager: intercept non-DDL always passes", "[schema]") {
    SchemaManagementConfig config;
    config.enabled = true;
    config.require_approval = true;

    SchemaManager mgr(config);

    // SELECT is not DDL, should always pass
    bool allowed = mgr.intercept_ddl("dev", "testdb",
        "SELECT * FROM test", StatementType::SELECT);
    REQUIRE(allowed == true);
    REQUIRE(mgr.pending_count() == 0);
}

TEST_CASE("SchemaManager: approve pending DDL", "[schema]") {
    SchemaManagementConfig config;
    config.enabled = true;
    config.require_approval = true;

    SchemaManager mgr(config);

    [[maybe_unused]] bool blocked = mgr.intercept_ddl("dev", "testdb",
        "ALTER TABLE test ADD COLUMN name TEXT", StatementType::ALTER_TABLE);

    auto pending = mgr.get_pending();
    REQUIRE(pending.size() == 1);
    std::string ddl_id = pending[0].id;

    bool approved = mgr.approve(ddl_id, "admin_user");
    REQUIRE(approved == true);
    REQUIRE(mgr.pending_count() == 0);

    // Should be in history as approved
    auto history = mgr.get_history();
    REQUIRE(!history.empty());
    bool found_approved = false;
    for (const auto& h : history) {
        if (h.status == "approved") {
            found_approved = true;
            break;
        }
    }
    REQUIRE(found_approved);
}

TEST_CASE("SchemaManager: reject pending DDL", "[schema]") {
    SchemaManagementConfig config;
    config.enabled = true;
    config.require_approval = true;

    SchemaManager mgr(config);

    [[maybe_unused]] bool blocked = mgr.intercept_ddl("dev", "testdb",
        "DROP TABLE important", StatementType::DROP_TABLE);

    auto pending = mgr.get_pending();
    REQUIRE(pending.size() == 1);
    std::string ddl_id = pending[0].id;

    bool rejected = mgr.reject(ddl_id, "admin_user");
    REQUIRE(rejected == true);
    REQUIRE(mgr.pending_count() == 0);

    // Should be in history as rejected
    auto history = mgr.get_history();
    bool found_rejected = false;
    for (const auto& h : history) {
        if (h.status == "rejected") {
            found_rejected = true;
            break;
        }
    }
    REQUIRE(found_rejected);
}

TEST_CASE("SchemaManager: approve nonexistent ID returns false", "[schema]") {
    SchemaManagementConfig config;
    config.enabled = true;
    config.require_approval = true;

    SchemaManager mgr(config);

    bool approved = mgr.approve("nonexistent-id", "admin");
    REQUIRE(approved == false);
}

TEST_CASE("SchemaManager: bounded history", "[schema]") {
    SchemaManagementConfig config;
    config.enabled = true;
    config.max_history_entries = 5;

    SchemaManager mgr(config);

    // Record more than max
    for (int i = 0; i < 10; ++i) {
        mgr.record_change("admin", "testdb", "table" + std::to_string(i),
            "ALTER TABLE test" + std::to_string(i), StatementType::ALTER_TABLE);
    }

    REQUIRE(mgr.history_size() == 5);

    // Newest entries should be present
    auto history = mgr.get_history("", "", 10);
    REQUIRE(history.size() == 5);
}

TEST_CASE("SchemaManager: history filter by database", "[schema]") {
    SchemaManagementConfig config;
    config.enabled = true;

    SchemaManager mgr(config);

    mgr.record_change("admin", "db1", "t1", "CREATE TABLE t1 (id INT)", StatementType::CREATE_TABLE);
    mgr.record_change("admin", "db2", "t2", "CREATE TABLE t2 (id INT)", StatementType::CREATE_TABLE);
    mgr.record_change("admin", "db1", "t3", "CREATE TABLE t3 (id INT)", StatementType::CREATE_TABLE);

    REQUIRE(mgr.history_size() == 3);

    auto db1_history = mgr.get_history("db1");
    REQUIRE(db1_history.size() == 2);

    auto db2_history = mgr.get_history("db2");
    REQUIRE(db2_history.size() == 1);
}
