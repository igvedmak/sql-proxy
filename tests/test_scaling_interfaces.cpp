#include <catch2/catch_test_macros.hpp>
#include "server/irate_limiter.hpp"
#include "server/rate_limiter.hpp"
#include "config/iconfig_store.hpp"
#include "core/types.hpp"

using namespace sqlproxy;

// ============================================================================
// IRateLimiter interface compliance
// ============================================================================

TEST_CASE("HierarchicalRateLimiter satisfies IRateLimiter", "[scaling]") {
    HierarchicalRateLimiter::Config cfg;
    cfg.global_tokens_per_second = 10000;
    cfg.global_burst_capacity = 1000;
    auto limiter = std::make_shared<HierarchicalRateLimiter>(cfg);

    // Can be used through the interface
    IRateLimiter* interface = limiter.get();
    auto result = interface->check("user", "db");
    CHECK(result.allowed);

    // Methods are callable through interface
    interface->set_user_limit("user", 100, 20);
    interface->set_database_limit("db", 100, 20);
    interface->set_user_database_limit("user", "db", 100, 20);
    interface->reset_all();
}

TEST_CASE("IRateLimiter polymorphism with shared_ptr", "[scaling]") {
    HierarchicalRateLimiter::Config cfg;
    cfg.global_tokens_per_second = 50000;
    cfg.global_burst_capacity = 10000;

    std::shared_ptr<IRateLimiter> limiter =
        std::make_shared<HierarchicalRateLimiter>(cfg);

    auto result = limiter->check("test_user", "test_db");
    CHECK(result.allowed);
}

// ============================================================================
// Statement type bitmask widening
// ============================================================================

TEST_CASE("stmt_mask supports prepared statement types", "[scaling]") {
    CHECK(stmt_mask::test(StatementType::PREPARE, stmt_mask::kPreparedStmt));
    CHECK(stmt_mask::test(StatementType::EXECUTE_STMT, stmt_mask::kPreparedStmt));
    CHECK(stmt_mask::test(StatementType::DEALLOCATE, stmt_mask::kPreparedStmt));

    // Existing masks still work
    CHECK(stmt_mask::test(StatementType::SELECT, stmt_mask::bit(StatementType::SELECT)));
    CHECK(stmt_mask::test(StatementType::INSERT, stmt_mask::kWrite));
    CHECK(stmt_mask::test(StatementType::INSERT, stmt_mask::kDML));
    CHECK(stmt_mask::test(StatementType::CREATE_TABLE, stmt_mask::kDDL));
    CHECK(stmt_mask::test(StatementType::BEGIN, stmt_mask::kTransaction));

    // Prepared stmts are NOT writes
    CHECK_FALSE(stmt_mask::test(StatementType::PREPARE, stmt_mask::kWrite));
    CHECK_FALSE(stmt_mask::test(StatementType::EXECUTE_STMT, stmt_mask::kDML));
}

// ============================================================================
// ReplicaConfig and DatabaseConfig
// ============================================================================

TEST_CASE("ReplicaConfig defaults", "[scaling]") {
    ReplicaConfig replica;
    CHECK(replica.connection_string.empty());
    CHECK(replica.min_connections == 2);
    CHECK(replica.max_connections == 5);
    CHECK(replica.weight == 1);
    CHECK(replica.health_check_query == "SELECT 1");
}

TEST_CASE("DatabaseConfig has replicas vector", "[scaling]") {
    DatabaseConfig cfg;
    CHECK(cfg.replicas.empty());

    cfg.replicas.push_back(ReplicaConfig{
        .connection_string = "postgresql://replica1:5432/db",
        .max_connections = 10,
        .weight = 2
    });
    CHECK(cfg.replicas.size() == 1);
    CHECK(cfg.replicas[0].weight == 2);
}

// ============================================================================
// ParsedQuery prepared statement fields
// ============================================================================

TEST_CASE("ParsedQuery has prepared statement fields", "[scaling]") {
    ParsedQuery pq;
    CHECK(pq.prepared_name.empty());
    CHECK(pq.prepared_params.empty());
    CHECK(pq.prepared_inner_sql.empty());

    pq.prepared_name = "my_stmt";
    pq.prepared_inner_sql = "SELECT * FROM customers WHERE id = $1";
    pq.prepared_params = {"42"};

    CHECK(pq.prepared_name == "my_stmt");
    CHECK(pq.prepared_params.size() == 1);
}

// ============================================================================
// statement_type_to_string for new types
// ============================================================================

TEST_CASE("statement_type_to_string includes prepared types", "[scaling]") {
    CHECK(std::string(statement_type_to_string(StatementType::PREPARE)) == "PREPARE");
    CHECK(std::string(statement_type_to_string(StatementType::EXECUTE_STMT)) == "EXECUTE");
    CHECK(std::string(statement_type_to_string(StatementType::DEALLOCATE)) == "DEALLOCATE");
}
