#include <catch2/catch_test_macros.hpp>
#include "db/generic_connection_pool.hpp"
#include "db/iconnection_factory.hpp"
#include "db/idb_connection.hpp"
#include <atomic>
#include <thread>

using namespace sqlproxy;

// Mock connection for testing
class MockConnection : public IDbConnection {
public:
    explicit MockConnection(int id) : id_(id), connected_(true) {}

    DbResultSet execute(const std::string&) override {
        DbResultSet rs;
        rs.success = true;
        return rs;
    }

    bool is_healthy(const std::string&) override { return connected_; }
    bool is_connected() const override { return connected_; }
    bool set_query_timeout(uint32_t) override { return true; }
    void close() override { connected_ = false; }

    int id() const { return id_; }

private:
    int id_;
    bool connected_;
};

// Mock factory that tracks connection creation
class MockFactory : public IConnectionFactory {
public:
    std::unique_ptr<IDbConnection> create(const std::string&) override {
        int id = next_id_.fetch_add(1);
        return std::make_unique<MockConnection>(id);
    }

    int total_created() const { return next_id_.load(); }

private:
    std::atomic<int> next_id_{0};
};

TEST_CASE("Pool: short max_lifetime causes connection recycling", "[pool][lifetime]") {
    auto factory = std::make_shared<MockFactory>();

    PoolConfig config;
    config.min_connections = 1;
    config.max_connections = 2;
    config.max_lifetime = std::chrono::seconds(1);  // 1 second lifetime

    GenericConnectionPool pool("test-db", config, factory);

    // First acquire: returns pre-warmed connection (id=0)
    {
        auto conn = pool.acquire();
        REQUIRE(conn != nullptr);
    }
    // Connection returned to pool

    // Wait for lifetime to expire
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));

    // Second acquire: should recycle (create new connection)
    {
        auto conn = pool.acquire();
        REQUIRE(conn != nullptr);
    }

    auto stats = pool.get_stats();
    CHECK(stats.connections_recycled >= 1);
}

TEST_CASE("Pool: max_lifetime=0 disables recycling", "[pool][lifetime]") {
    auto factory = std::make_shared<MockFactory>();

    PoolConfig config;
    config.min_connections = 1;
    config.max_connections = 2;
    config.max_lifetime = std::chrono::seconds(0);  // Disabled

    GenericConnectionPool pool("test-db", config, factory);

    // Acquire and return
    {
        auto conn = pool.acquire();
        REQUIRE(conn != nullptr);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Acquire again - should reuse same connection (no recycling)
    {
        auto conn = pool.acquire();
        REQUIRE(conn != nullptr);
    }

    auto stats = pool.get_stats();
    CHECK(stats.connections_recycled == 0);
    // Only 1 connection created (pre-warm), no recycling
    CHECK(factory->total_created() == 1);
}

TEST_CASE("Pool: connection within lifetime is reused", "[pool][lifetime]") {
    auto factory = std::make_shared<MockFactory>();

    PoolConfig config;
    config.min_connections = 1;
    config.max_connections = 2;
    config.max_lifetime = std::chrono::seconds(60);  // Long lifetime

    GenericConnectionPool pool("test-db", config, factory);

    // Acquire and return quickly
    {
        auto conn = pool.acquire();
        REQUIRE(conn != nullptr);
    }

    // Immediate re-acquire - should reuse
    {
        auto conn = pool.acquire();
        REQUIRE(conn != nullptr);
    }

    auto stats = pool.get_stats();
    CHECK(stats.connections_recycled == 0);
    CHECK(factory->total_created() == 1);  // Only pre-warm connection
}

TEST_CASE("Pool: recycled counter increments for each recycled connection", "[pool][lifetime]") {
    auto factory = std::make_shared<MockFactory>();

    PoolConfig config;
    config.min_connections = 1;
    config.max_connections = 2;
    config.max_lifetime = std::chrono::seconds(1);

    GenericConnectionPool pool("test-db", config, factory);

    // Cycle: acquire, return, wait for expiry, acquire (recycle)
    for (int i = 0; i < 3; ++i) {
        {
            auto conn = pool.acquire();
            REQUIRE(conn != nullptr);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    }

    // Final acquire triggers last recycle
    {
        auto conn = pool.acquire();
        REQUIRE(conn != nullptr);
    }

    auto stats = pool.get_stats();
    CHECK(stats.connections_recycled >= 3);
}
