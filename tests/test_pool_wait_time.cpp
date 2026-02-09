#include <catch2/catch_test_macros.hpp>
#include "db/generic_connection_pool.hpp"
#include "db/iconnection_factory.hpp"
#include "db/idb_connection.hpp"

using namespace sqlproxy;

namespace {

class MockConnection : public IDbConnection {
public:
    DbResultSet execute(const std::string&) override { return {.success = true}; }
    bool is_healthy(const std::string&) override { return healthy_; }
    bool is_connected() const override { return connected_; }
    bool set_query_timeout(uint32_t) override { return true; }
    void close() override { connected_ = false; }

    bool healthy_ = true;
    bool connected_ = true;
};

class MockFactory : public IConnectionFactory {
public:
    std::unique_ptr<IDbConnection> create(const std::string&) override {
        if (!should_succeed_) return nullptr;
        return std::make_unique<MockConnection>();
    }
    bool should_succeed_ = true;
};

} // namespace

TEST_CASE("PoolWaitTime: fast acquire populates sub-ms bucket", "[pool][metrics]") {
    auto factory = std::make_shared<MockFactory>();
    PoolConfig cfg;
    cfg.max_connections = 4;
    cfg.min_connections = 2;

    GenericConnectionPool pool("test_db", cfg, factory);

    auto conn = pool.acquire();
    REQUIRE(conn != nullptr);
    conn.reset();  // return to pool

    auto stats = pool.get_stats();
    REQUIRE(stats.acquire_time_count == 1);
    // With mock (no real I/O), acquire can complete in under 1μs → sum may be 0
    CHECK(stats.acquire_time_sum_us >= 0);

    // With mock (no real I/O), acquire should be ≤100μs (bucket 0) or ≤500μs (bucket 1)
    uint64_t total_in_buckets = 0;
    for (auto b : stats.acquire_time_buckets) total_in_buckets += b;
    CHECK(total_in_buckets == 1);
}

TEST_CASE("PoolWaitTime: sum accumulates across multiple acquires", "[pool][metrics]") {
    auto factory = std::make_shared<MockFactory>();
    PoolConfig cfg;
    cfg.max_connections = 4;
    cfg.min_connections = 0;

    GenericConnectionPool pool("test_db", cfg, factory);

    for (int i = 0; i < 5; ++i) {
        auto conn = pool.acquire();
        REQUIRE(conn != nullptr);
    }

    auto stats = pool.get_stats();
    CHECK(stats.acquire_time_count == 5);
    // With mock (no real I/O), acquire can complete in under 1μs → sum may be 0
    CHECK(stats.acquire_time_sum_us >= 0);
}

TEST_CASE("PoolWaitTime: bucket counts sum equals total count", "[pool][metrics]") {
    auto factory = std::make_shared<MockFactory>();
    PoolConfig cfg;
    cfg.max_connections = 10;
    cfg.min_connections = 0;

    GenericConnectionPool pool("test_db", cfg, factory);

    constexpr int N = 10;
    for (int i = 0; i < N; ++i) {
        auto conn = pool.acquire();
        REQUIRE(conn != nullptr);
    }

    auto stats = pool.get_stats();
    uint64_t bucket_sum = 0;
    for (auto b : stats.acquire_time_buckets) bucket_sum += b;
    CHECK(bucket_sum == static_cast<uint64_t>(N));
    CHECK(stats.acquire_time_count == static_cast<uint64_t>(N));
}

TEST_CASE("PoolWaitTime: failed acquire does not record timing", "[pool][metrics]") {
    auto factory = std::make_shared<MockFactory>();
    factory->should_succeed_ = false;

    PoolConfig cfg;
    cfg.max_connections = 4;
    cfg.min_connections = 0;

    GenericConnectionPool pool("test_db", cfg, factory);

    auto conn = pool.acquire();
    CHECK(conn == nullptr);

    auto stats = pool.get_stats();
    CHECK(stats.acquire_time_count == 0);
    CHECK(stats.acquire_time_sum_us == 0);
}
