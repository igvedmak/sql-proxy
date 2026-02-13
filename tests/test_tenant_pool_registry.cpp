#include <catch2/catch_test_macros.hpp>
#include "db/tenant_pool_registry.hpp"
#include "db/iconnection_pool.hpp"
#include "db/pooled_connection.hpp"

using namespace sqlproxy;

// ---------------------------------------------------------------------------
// Mock IConnectionPool for testing
// ---------------------------------------------------------------------------
class MockTenantPool : public IConnectionPool {
public:
    explicit MockTenantPool(std::string name) : name_(std::move(name)) {}

    [[nodiscard]] std::unique_ptr<PooledConnection> acquire(
        std::chrono::milliseconds /*timeout*/) override {
        return nullptr; // Not needed for registry tests
    }

    [[nodiscard]] PoolStats get_stats() const override { return {}; }

    void drain() override {}

    [[nodiscard]] const std::string& name() const override { return name_; }

private:
    std::string name_;
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST_CASE("TenantPoolRegistry: get_pool returns nullptr when no factory set",
          "[tenant_pool_registry]") {
    TenantPoolRegistry registry;

    auto pool = registry.get_pool("acme", "testdb");
    REQUIRE(pool == nullptr);
}

TEST_CASE("TenantPoolRegistry: get_pool creates pool via factory on first call",
          "[tenant_pool_registry]") {
    TenantPoolRegistry registry;

    int factory_calls = 0;
    registry.set_pool_factory(
        [&](const std::string& tenant, const std::string& db, size_t max_conn) {
            ++factory_calls;
            REQUIRE(tenant == "acme");
            REQUIRE(db == "testdb");
            REQUIRE(max_conn == 10); // default
            return std::make_shared<MockTenantPool>(tenant + ":" + db);
        });

    auto pool = registry.get_pool("acme", "testdb");
    REQUIRE(pool != nullptr);
    REQUIRE(pool->name() == "acme:testdb");
    REQUIRE(factory_calls == 1);
}

TEST_CASE("TenantPoolRegistry: get_pool returns same pool on second call (cache hit)",
          "[tenant_pool_registry]") {
    TenantPoolRegistry registry;

    int factory_calls = 0;
    registry.set_pool_factory(
        [&](const std::string& tenant, const std::string& db, size_t /*max_conn*/) {
            ++factory_calls;
            return std::make_shared<MockTenantPool>(tenant + ":" + db);
        });

    auto pool1 = registry.get_pool("acme", "testdb");
    auto pool2 = registry.get_pool("acme", "testdb");

    REQUIRE(pool1 != nullptr);
    REQUIRE(pool2 != nullptr);
    REQUIRE(pool1.get() == pool2.get()); // Same object
    REQUIRE(factory_calls == 1);         // Factory called only once
}

TEST_CASE("TenantPoolRegistry: set_tenant_config respects max_connections",
          "[tenant_pool_registry]") {
    TenantPoolRegistry registry;

    size_t captured_max_conn = 0;
    registry.set_pool_factory(
        [&](const std::string& tenant, const std::string& db, size_t max_conn) {
            captured_max_conn = max_conn;
            return std::make_shared<MockTenantPool>(tenant + ":" + db);
        });

    // Set custom max connections BEFORE first get_pool call
    registry.set_tenant_config("bigcorp", "analytics", 50);

    auto pool = registry.get_pool("bigcorp", "analytics");
    REQUIRE(pool != nullptr);
    REQUIRE(captured_max_conn == 50);
}

TEST_CASE("TenantPoolRegistry: get_stats returns correct counts",
          "[tenant_pool_registry]") {
    TenantPoolRegistry registry;

    registry.set_pool_factory(
        [](const std::string& tenant, const std::string& db, size_t /*max_conn*/) {
            return std::make_shared<MockTenantPool>(tenant + ":" + db);
        });

    // Empty initially
    auto stats0 = registry.get_stats();
    REQUIRE(stats0.total_pools == 0);
    REQUIRE(stats0.total_tenants == 0);

    // Create pools for 2 tenants across 3 databases
    (void)registry.get_pool("acme", "db1");
    (void)registry.get_pool("acme", "db2");
    (void)registry.get_pool("globex", "db1");

    auto stats1 = registry.get_stats();
    REQUIRE(stats1.total_pools == 3);
    REQUIRE(stats1.total_tenants == 2);
}
