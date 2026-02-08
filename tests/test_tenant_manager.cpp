#include <catch2/catch_test_macros.hpp>
#include "tenant/tenant_manager.hpp"
#include "policy/policy_engine.hpp"
#include "server/rate_limiter.hpp"
#include "audit/audit_emitter.hpp"

using namespace sqlproxy;

TEST_CASE("TenantManager: basic construction", "[tenant]") {
    TenantConfig config;
    config.enabled = true;
    config.default_tenant = "default";
    config.header_name = "X-Tenant-Id";

    TenantManager mgr(config);
    REQUIRE(mgr.tenant_count() == 0);
    REQUIRE(mgr.config().enabled == true);
    REQUIRE(mgr.config().default_tenant == "default");
}

TEST_CASE("TenantManager: register and resolve tenant", "[tenant]") {
    TenantConfig config;
    config.enabled = true;
    config.default_tenant = "default";

    TenantManager mgr(config);

    auto ctx = std::make_shared<TenantContext>();
    ctx->tenant_id = "acme";
    ctx->policy_engine = std::make_shared<PolicyEngine>();

    mgr.register_tenant("acme", ctx);
    REQUIRE(mgr.tenant_count() == 1);

    auto resolved = mgr.resolve("acme");
    REQUIRE(resolved != nullptr);
    REQUIRE(resolved->tenant_id == "acme");
    REQUIRE(resolved->policy_engine != nullptr);
}

TEST_CASE("TenantManager: resolve unknown returns nullptr", "[tenant]") {
    TenantConfig config;
    config.enabled = true;
    config.default_tenant = "default";

    TenantManager mgr(config);

    auto resolved = mgr.resolve("nonexistent");
    REQUIRE(resolved == nullptr);
}

TEST_CASE("TenantManager: default tenant fallback", "[tenant]") {
    TenantConfig config;
    config.enabled = true;
    config.default_tenant = "default";

    TenantManager mgr(config);

    auto default_ctx = std::make_shared<TenantContext>();
    default_ctx->tenant_id = "default";
    mgr.register_tenant("default", default_ctx);

    // Resolve unknown falls back to default tenant
    auto resolved = mgr.resolve("unknown");
    REQUIRE(resolved != nullptr);
    REQUIRE(resolved->tenant_id == "default");

    // Resolve default by name
    auto def = mgr.resolve("default");
    REQUIRE(def != nullptr);
    REQUIRE(def->tenant_id == "default");
}

TEST_CASE("TenantManager: tenant isolation", "[tenant]") {
    TenantConfig config;
    config.enabled = true;

    TenantManager mgr(config);

    auto ctx1 = std::make_shared<TenantContext>();
    ctx1->tenant_id = "tenant1";
    ctx1->policy_engine = std::make_shared<PolicyEngine>();

    auto ctx2 = std::make_shared<TenantContext>();
    ctx2->tenant_id = "tenant2";
    ctx2->policy_engine = std::make_shared<PolicyEngine>();

    // Load different policies per tenant
    Policy allow_all;
    allow_all.name = "allow_all";
    allow_all.priority = 50;
    allow_all.action = Decision::ALLOW;
    allow_all.users = {"*"};
    ctx1->policy_engine->load_policies({allow_all});

    Policy deny_all;
    deny_all.name = "deny_all";
    deny_all.priority = 50;
    deny_all.action = Decision::BLOCK;
    deny_all.users = {"*"};
    ctx2->policy_engine->load_policies({deny_all});

    mgr.register_tenant("tenant1", ctx1);
    mgr.register_tenant("tenant2", ctx2);

    REQUIRE(mgr.tenant_count() == 2);

    auto t1 = mgr.resolve("tenant1");
    auto t2 = mgr.resolve("tenant2");
    REQUIRE(t1->policy_engine != t2->policy_engine);
    REQUIRE(t1->policy_engine->policy_count() == 1);
    REQUIRE(t2->policy_engine->policy_count() == 1);
}

TEST_CASE("TenantManager: hot-reload tenants", "[tenant]") {
    TenantConfig config;
    config.enabled = true;

    TenantManager mgr(config);

    // Register initial tenant
    auto ctx1 = std::make_shared<TenantContext>();
    ctx1->tenant_id = "old";
    mgr.register_tenant("old", ctx1);
    REQUIRE(mgr.tenant_count() == 1);

    // Hot-reload with entirely new set
    std::unordered_map<std::string, std::shared_ptr<TenantContext>> new_tenants;
    auto ctx2 = std::make_shared<TenantContext>();
    ctx2->tenant_id = "new1";
    new_tenants["new1"] = ctx2;
    auto ctx3 = std::make_shared<TenantContext>();
    ctx3->tenant_id = "new2";
    new_tenants["new2"] = ctx3;

    mgr.reload_tenants(std::move(new_tenants));
    REQUIRE(mgr.tenant_count() == 2);
    REQUIRE(mgr.resolve("old") == nullptr);
    REQUIRE(mgr.resolve("new1") != nullptr);
    REQUIRE(mgr.resolve("new2") != nullptr);
}

TEST_CASE("TenantManager: thread safety - concurrent resolve", "[tenant]") {
    TenantConfig config;
    config.enabled = true;

    TenantManager mgr(config);

    auto ctx = std::make_shared<TenantContext>();
    ctx->tenant_id = "concurrent";
    mgr.register_tenant("concurrent", ctx);

    // Multiple threads resolving simultaneously
    std::vector<std::jthread> threads;
    std::atomic<int> success_count{0};

    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&mgr, &success_count]() {
            for (int j = 0; j < 1000; ++j) {
                auto resolved = mgr.resolve("concurrent");
                if (resolved && resolved->tenant_id == "concurrent") {
                    success_count.fetch_add(1);
                }
            }
        });
    }

    threads.clear(); // join all
    REQUIRE(success_count.load() == 8000);
}

TEST_CASE("TenantManager: register overwrites existing", "[tenant]") {
    TenantConfig config;
    config.enabled = true;

    TenantManager mgr(config);

    auto ctx1 = std::make_shared<TenantContext>();
    ctx1->tenant_id = "tenant1";
    ctx1->policy_engine = std::make_shared<PolicyEngine>();
    mgr.register_tenant("tenant1", ctx1);

    auto original_engine = mgr.resolve("tenant1")->policy_engine;

    // Re-register with different context
    auto ctx2 = std::make_shared<TenantContext>();
    ctx2->tenant_id = "tenant1";
    ctx2->policy_engine = std::make_shared<PolicyEngine>();
    mgr.register_tenant("tenant1", ctx2);

    // Should be updated
    auto resolved = mgr.resolve("tenant1");
    REQUIRE(resolved->policy_engine != original_engine);
    REQUIRE(mgr.tenant_count() == 1);
}
