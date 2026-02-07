#include <catch2/catch_test_macros.hpp>
#include "db/database_router.hpp"
#include "mocks/mock_query_executor.hpp"

using namespace sqlproxy;
using namespace sqlproxy::testing;

TEST_CASE("DatabaseRouter register and lookup executor", "[router]") {
    DatabaseRouter router;
    auto exec = std::make_shared<MockQueryExecutor>(true, "testdb");
    router.register_executor("testdb", exec);

    auto found = router.get_executor("testdb");
    REQUIRE(found != nullptr);

    auto result = found->execute("SELECT 1", StatementType::SELECT);
    CHECK(result.success);
    CHECK(result.rows[0][0] == "testdb");
}

TEST_CASE("DatabaseRouter unknown database returns nullptr", "[router]") {
    DatabaseRouter router;
    CHECK(router.get_executor("nonexistent") == nullptr);
    CHECK(router.get_parser("nonexistent") == nullptr);
}

TEST_CASE("DatabaseRouter has_database", "[router]") {
    DatabaseRouter router;
    CHECK_FALSE(router.has_database("testdb"));

    router.register_executor("testdb", std::make_shared<MockQueryExecutor>());
    CHECK(router.has_database("testdb"));
}

TEST_CASE("DatabaseRouter database_names", "[router]") {
    DatabaseRouter router;
    router.register_executor("db1", std::make_shared<MockQueryExecutor>());
    router.register_executor("db2", std::make_shared<MockQueryExecutor>());

    auto names = router.database_names();
    CHECK(names.size() == 2);

    // Sort for deterministic comparison
    std::sort(names.begin(), names.end());
    CHECK(names[0] == "db1");
    CHECK(names[1] == "db2");
}

TEST_CASE("DatabaseRouter multiple databases", "[router]") {
    DatabaseRouter router;
    auto exec1 = std::make_shared<MockQueryExecutor>(true, "primary");
    auto exec2 = std::make_shared<MockQueryExecutor>(true, "analytics");

    router.register_executor("primary_db", exec1);
    router.register_executor("analytics_db", exec2);

    auto r1 = router.get_executor("primary_db")->execute("SELECT 1", StatementType::SELECT);
    auto r2 = router.get_executor("analytics_db")->execute("SELECT 1", StatementType::SELECT);

    CHECK(r1.rows[0][0] == "primary");
    CHECK(r2.rows[0][0] == "analytics");
}

TEST_CASE("DatabaseRouter overwrite executor", "[router]") {
    DatabaseRouter router;
    auto exec1 = std::make_shared<MockQueryExecutor>(true, "old");
    auto exec2 = std::make_shared<MockQueryExecutor>(true, "new");

    router.register_executor("testdb", exec1);
    router.register_executor("testdb", exec2);

    auto result = router.get_executor("testdb")->execute("SELECT 1", StatementType::SELECT);
    CHECK(result.rows[0][0] == "new");
}
