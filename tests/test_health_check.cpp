#include <catch2/catch_test_macros.hpp>
#include "executor/circuit_breaker.hpp"
#include "db/generic_connection_pool.hpp"
#include "db/iconnection_factory.hpp"
#include "parser/parse_cache.hpp"

using namespace sqlproxy;

// Mock connection for pool tests
class HealthCheckMockConnection : public IDbConnection {
public:
    DbResultSet execute(const std::string&) override {
        DbResultSet rs;
        rs.success = true;
        return rs;
    }
    bool is_healthy(const std::string&) override { return true; }
    bool is_connected() const override { return true; }
    bool set_query_timeout(uint32_t) override { return true; }
    void close() override {}
};

class HealthCheckMockFactory : public IConnectionFactory {
public:
    std::unique_ptr<IDbConnection> create(const std::string&) override {
        return std::make_unique<HealthCheckMockConnection>();
    }
};

TEST_CASE("HealthCheck: circuit breaker CLOSED is healthy", "[health_check][deep]") {
    CircuitBreaker::Config cfg;
    cfg.failure_threshold = 5;
    CircuitBreaker cb("test", cfg);

    CHECK(cb.get_state() == CircuitState::CLOSED);
    // Deep health check would pass for CLOSED state
    CHECK(cb.allow_request() == true);
}

TEST_CASE("HealthCheck: circuit breaker OPEN is unhealthy", "[health_check][deep]") {
    CircuitBreaker::Config cfg;
    cfg.failure_threshold = 2;
    cfg.timeout = std::chrono::milliseconds(60000); // Long timeout so it stays OPEN
    CircuitBreaker cb("test", cfg);

    cb.record_failure(FailureCategory::INFRASTRUCTURE);
    cb.record_failure(FailureCategory::INFRASTRUCTURE);

    CHECK(cb.get_state() == CircuitState::OPEN);
    // Deep health check would fail for OPEN state
    CHECK(cb.allow_request() == false);
}

TEST_CASE("HealthCheck: pool has idle connections when healthy", "[health_check][deep]") {
    auto factory = std::make_shared<HealthCheckMockFactory>();
    PoolConfig config;
    config.min_connections = 2;
    config.max_connections = 5;

    GenericConnectionPool pool("test-db", config, factory);

    auto stats = pool.get_stats();
    CHECK(stats.idle_connections >= 1);  // Pre-warmed connections are idle
}

TEST_CASE("HealthCheck: parse cache stats accessible", "[health_check][deep]") {
    ParseCache cache(1000, 4);

    auto stats = cache.get_stats();
    CHECK(stats.total_entries == 0);
    CHECK(stats.hits == 0);
    CHECK(stats.misses == 0);
    CHECK(stats.ddl_invalidations == 0);
}

TEST_CASE("HealthCheck: all components healthy simultaneously", "[health_check][deep]") {
    // Circuit breaker: CLOSED
    CircuitBreaker::Config cb_cfg;
    cb_cfg.failure_threshold = 10;
    CircuitBreaker cb("test", cb_cfg);
    CHECK(cb.get_state() == CircuitState::CLOSED);

    // Pool: has idle connections
    auto factory = std::make_shared<HealthCheckMockFactory>();
    PoolConfig pool_cfg;
    pool_cfg.min_connections = 2;
    pool_cfg.max_connections = 5;
    GenericConnectionPool pool("test-db", pool_cfg, factory);
    auto pool_stats = pool.get_stats();
    CHECK(pool_stats.idle_connections >= 1);

    // Cache: operational
    ParseCache cache(1000, 4);
    auto cache_stats = cache.get_stats();
    CHECK(cache_stats.total_entries == 0);

    // All conditions that /health?level=deep checks are met
    bool cb_healthy = (cb.get_state() == CircuitState::CLOSED);
    bool pool_healthy = (pool_stats.idle_connections > 0);
    bool all_healthy = cb_healthy && pool_healthy;
    CHECK(all_healthy);
}
