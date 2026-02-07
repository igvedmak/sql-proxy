#include <catch2/catch_test_macros.hpp>
#include "db/routing_query_executor.hpp"
#include "executor/circuit_breaker.hpp"
#include "mocks/mock_query_executor.hpp"

using namespace sqlproxy;
using namespace sqlproxy::testing;

static RoutingQueryExecutor make_executor(
    bool primary_ok = true, bool replica_ok = true, int num_replicas = 2) {
    auto primary = std::make_shared<MockQueryExecutor>(primary_ok, "primary");
    std::vector<RoutingQueryExecutor::ReplicaEntry> replicas;
    for (int i = 0; i < num_replicas; ++i) {
        auto cb = std::make_shared<CircuitBreaker>("replica_" + std::to_string(i));
        auto exec = std::make_shared<MockQueryExecutor>(replica_ok, "replica_" + std::to_string(i));
        replicas.push_back({exec, cb, 1});
    }
    return RoutingQueryExecutor(primary, std::move(replicas));
}

TEST_CASE("RoutingQueryExecutor: SELECT goes to replica", "[routing]") {
    auto executor = make_executor();
    auto result = executor.execute("SELECT 1", StatementType::SELECT);

    CHECK(result.success);
    // Should be from a replica
    CHECK(result.rows[0][0].starts_with("replica_"));
}

TEST_CASE("RoutingQueryExecutor: INSERT goes to primary", "[routing]") {
    auto executor = make_executor();
    auto result = executor.execute("INSERT INTO t VALUES (1)", StatementType::INSERT);

    CHECK(result.success);
    CHECK(result.rows[0][0] == "primary");
}

TEST_CASE("RoutingQueryExecutor: UPDATE goes to primary", "[routing]") {
    auto executor = make_executor();
    auto result = executor.execute("UPDATE t SET x=1", StatementType::UPDATE);

    CHECK(result.success);
    CHECK(result.rows[0][0] == "primary");
}

TEST_CASE("RoutingQueryExecutor: DELETE goes to primary", "[routing]") {
    auto executor = make_executor();
    auto result = executor.execute("DELETE FROM t", StatementType::DELETE);

    CHECK(result.success);
    CHECK(result.rows[0][0] == "primary");
}

TEST_CASE("RoutingQueryExecutor: DDL goes to primary", "[routing]") {
    auto executor = make_executor();
    auto result = executor.execute("CREATE TABLE t (id INT)", StatementType::CREATE_TABLE);

    CHECK(result.success);
    CHECK(result.rows[0][0] == "primary");
}

TEST_CASE("RoutingQueryExecutor: no replicas falls back to primary", "[routing]") {
    auto primary = std::make_shared<MockQueryExecutor>(true, "primary");
    RoutingQueryExecutor executor(primary, {});

    auto result = executor.execute("SELECT 1", StatementType::SELECT);
    CHECK(result.success);
    CHECK(result.rows[0][0] == "primary");
}

TEST_CASE("RoutingQueryExecutor: replica failure falls back to primary", "[routing]") {
    auto executor = make_executor(true, false);
    auto result = executor.execute("SELECT 1", StatementType::SELECT);

    CHECK(result.success);
    CHECK(result.rows[0][0] == "primary");
}

TEST_CASE("RoutingQueryExecutor: healthy_replica_count", "[routing]") {
    auto executor = make_executor(true, true, 3);
    CHECK(executor.healthy_replica_count() == 3);
}

TEST_CASE("RoutingQueryExecutor: round-robin distribution", "[routing]") {
    auto primary = std::make_shared<MockQueryExecutor>(true, "primary");
    auto replica0 = std::make_shared<MockQueryExecutor>(true, "r0");
    auto replica1 = std::make_shared<MockQueryExecutor>(true, "r1");

    std::vector<RoutingQueryExecutor::ReplicaEntry> replicas;
    replicas.push_back({replica0, std::make_shared<CircuitBreaker>("r0"), 1});
    replicas.push_back({replica1, std::make_shared<CircuitBreaker>("r1"), 1});

    RoutingQueryExecutor executor(primary, std::move(replicas));

    // Execute 100 SELECTs
    for (int i = 0; i < 100; ++i) {
        (void)executor.execute("SELECT 1", StatementType::SELECT);
    }

    // Both replicas should have received requests
    CHECK(replica0->execute_count() > 0);
    CHECK(replica1->execute_count() > 0);
    // Total should be 100 (each SELECT served by exactly one replica)
    CHECK(replica0->execute_count() + replica1->execute_count() == 100);
}
