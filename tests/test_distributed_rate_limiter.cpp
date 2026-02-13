#include <catch2/catch_test_macros.hpp>
#include "server/distributed_rate_limiter.hpp"
#include "server/rate_limiter.hpp"
#include <thread>
#include <chrono>

using namespace sqlproxy;

static std::shared_ptr<HierarchicalRateLimiter> make_local_limiter() {
    HierarchicalRateLimiter::Config cfg;
    cfg.global_tokens_per_second = 1000;
    cfg.global_burst_capacity = 100;
    cfg.default_user_tokens_per_second = 100;
    cfg.default_user_burst_capacity = 20;
    cfg.default_db_tokens_per_second = 500;
    cfg.default_db_burst_capacity = 50;
    cfg.default_user_db_tokens_per_second = 50;
    cfg.default_user_db_burst_capacity = 10;
    cfg.bucket_idle_timeout_seconds = 0; // disable cleanup for tests
    return std::make_shared<HierarchicalRateLimiter>(cfg);
}

TEST_CASE("DistributedRateLimiter", "[distributed_rate_limiter]") {

    SECTION("Disabled passes through to local limiter") {
        auto local = make_local_limiter();
        auto backend = std::make_shared<InMemoryDistributedBackend>(1);
        DistributedRateLimiter::Config cfg;
        cfg.enabled = false;
        cfg.cluster_size = 1;

        DistributedRateLimiter drl(local, backend, cfg);
        REQUIRE_FALSE(drl.is_enabled());

        auto result = drl.check("user1", "db1");
        REQUIRE(result.allowed);
    }

    SECTION("Single-node cluster behaves like local limiter") {
        auto local = make_local_limiter();
        auto backend = std::make_shared<InMemoryDistributedBackend>(1);
        DistributedRateLimiter::Config cfg;
        cfg.enabled = true;
        cfg.node_id = "node-1";
        cfg.cluster_size = 1;
        cfg.sync_interval_ms = 100;

        DistributedRateLimiter drl(local, backend, cfg);

        auto result = drl.check("user1", "db1");
        REQUIRE(result.allowed);

        auto stats = drl.get_stats();
        REQUIRE(stats.total_checks == 1);
    }

    SECTION("Budget division with cluster_size > 1") {
        auto local = make_local_limiter();
        auto backend = std::make_shared<InMemoryDistributedBackend>(4);
        DistributedRateLimiter::Config cfg;
        cfg.enabled = true;
        cfg.node_id = "node-1";
        cfg.cluster_size = 4;
        cfg.sync_interval_ms = 100;

        DistributedRateLimiter drl(local, backend, cfg);

        // Set a limit of 100 TPS — each node should get 25
        drl.set_user_limit("test_user", 100, 20);

        // The first few requests should pass
        auto result = drl.check("test_user", "db1");
        REQUIRE(result.allowed);
    }

    SECTION("Backend sync reports usage") {
        auto local = make_local_limiter();
        auto backend = std::make_shared<InMemoryDistributedBackend>(2);
        DistributedRateLimiter::Config cfg;
        cfg.enabled = true;
        cfg.node_id = "node-1";
        cfg.cluster_size = 2;
        cfg.sync_interval_ms = 50; // 50ms for fast test

        DistributedRateLimiter drl(local, backend, cfg);

        // Generate some usage
        drl.check("user1", "db1");
        drl.check("user1", "db1");
        drl.check("user1", "db1");

        // Start sync and wait for one cycle
        drl.start_sync();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        drl.stop_sync();

        auto stats = drl.get_stats();
        REQUIRE(stats.sync_cycles >= 1);
        REQUIRE(stats.total_checks == 3);
    }

    SECTION("InMemoryDistributedBackend tracks usage") {
        InMemoryDistributedBackend backend(3);

        REQUIRE(backend.node_count() == 3);
        REQUIRE(backend.get_global_usage("key1") == 0);

        backend.report_usage("key1", 10);
        backend.report_usage("key1", 5);
        REQUIRE(backend.get_global_usage("key1") == 15);

        backend.reset();
        REQUIRE(backend.get_global_usage("key1") == 0);
    }

    SECTION("Reset clears local and backend") {
        auto local = make_local_limiter();
        auto backend = std::make_shared<InMemoryDistributedBackend>(1);
        DistributedRateLimiter::Config cfg;
        cfg.enabled = true;
        cfg.cluster_size = 1;

        DistributedRateLimiter drl(local, backend, cfg);

        drl.check("user1", "db1");
        backend->report_usage("user1:db1", 5);
        REQUIRE(backend->get_global_usage("user1:db1") == 5);

        drl.reset_all();
        REQUIRE(backend->get_global_usage("user1:db1") == 0);
    }
}
