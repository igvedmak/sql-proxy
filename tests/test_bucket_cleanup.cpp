#include <catch2/catch_test_macros.hpp>
#include "server/rate_limiter.hpp"
#include <thread>

using namespace sqlproxy;

TEST_CASE("BucketCleanup: idle buckets evicted after timeout", "[rate_limiter][cleanup]") {
    HierarchicalRateLimiter::Config cfg;
    cfg.bucket_idle_timeout_seconds = 1;   // 1 second timeout
    cfg.cleanup_interval_seconds = 1;       // Check every 1 second

    HierarchicalRateLimiter limiter(cfg);

    // Create user + db buckets by checking them
    (void)limiter.check("user1", "db1");
    (void)limiter.check("user2", "db2");

    auto stats_before = limiter.get_stats();
    CHECK(stats_before.user_bucket_count == 2);
    CHECK(stats_before.db_bucket_count == 2);

    // Wait for idle timeout + cleanup interval to elapse
    std::this_thread::sleep_for(std::chrono::milliseconds(2500));

    auto stats_after = limiter.get_stats();
    CHECK(stats_after.user_bucket_count == 0);
    CHECK(stats_after.db_bucket_count == 0);
    CHECK(stats_after.user_db_bucket_count == 0);
    CHECK(stats_after.buckets_evicted > 0);
}

TEST_CASE("BucketCleanup: active buckets not evicted", "[rate_limiter][cleanup]") {
    HierarchicalRateLimiter::Config cfg;
    cfg.bucket_idle_timeout_seconds = 2;
    cfg.cleanup_interval_seconds = 1;

    HierarchicalRateLimiter limiter(cfg);

    // Create buckets and keep them active
    (void)limiter.check("active-user", "active-db");

    // Keep refreshing within idle timeout
    for (int i = 0; i < 5; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        (void)limiter.check("active-user", "active-db");
    }

    auto stats = limiter.get_stats();
    CHECK(stats.user_bucket_count == 1);
    CHECK(stats.db_bucket_count == 1);
    CHECK(stats.user_db_bucket_count == 1);
}

TEST_CASE("BucketCleanup: last_access_ns updates on try_acquire", "[rate_limiter][cleanup]") {
    TokenBucket bucket(1000, 100);

    auto ns1 = bucket.last_access_ns();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    (void)bucket.try_acquire();
    auto ns2 = bucket.last_access_ns();

    CHECK(ns2 > ns1);
}

TEST_CASE("BucketCleanup: eviction counter tracks correctly", "[rate_limiter][cleanup]") {
    HierarchicalRateLimiter::Config cfg;
    cfg.bucket_idle_timeout_seconds = 1;
    cfg.cleanup_interval_seconds = 1;

    HierarchicalRateLimiter limiter(cfg);

    // Create 3 users × 1 db = 3 user + 1 db + 3 user-db = 7 buckets
    (void)limiter.check("u1", "db1");
    (void)limiter.check("u2", "db1");
    (void)limiter.check("u3", "db1");

    auto stats_before = limiter.get_stats();
    CHECK(stats_before.user_bucket_count == 3);
    CHECK(stats_before.db_bucket_count == 1);
    CHECK(stats_before.user_db_bucket_count == 3);

    // Wait for all to expire and be cleaned up
    std::this_thread::sleep_for(std::chrono::milliseconds(2500));

    auto stats_after = limiter.get_stats();
    CHECK(stats_after.buckets_evicted == 7);  // 3 user + 1 db + 3 user-db
}
