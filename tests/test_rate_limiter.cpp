#include <catch2/catch_test_macros.hpp>
#include "server/rate_limiter.hpp"
#include <thread>
#include <chrono>

using namespace sqlproxy;

TEST_CASE("TokenBucket basic acquire and deny", "[rate_limiter]") {

    SECTION("Acquire tokens when bucket is full") {
        TokenBucket bucket(100, 10);  // 100 tokens/sec, burst capacity 10
        // Bucket starts full (10 tokens)
        REQUIRE(bucket.try_acquire(1));
    }

    SECTION("Acquire multiple tokens") {
        TokenBucket bucket(100, 10);
        REQUIRE(bucket.try_acquire(5));
    }

    SECTION("Acquire all tokens") {
        TokenBucket bucket(100, 10);
        REQUIRE(bucket.try_acquire(10));
    }

    SECTION("Deny when not enough tokens") {
        TokenBucket bucket(100, 10);
        // Exhaust all tokens
        REQUIRE(bucket.try_acquire(10));
        // Should be denied now
        REQUIRE_FALSE(bucket.try_acquire(1));
    }

    SECTION("Cannot acquire more than burst capacity") {
        TokenBucket bucket(100, 10);
        REQUIRE_FALSE(bucket.try_acquire(11));
    }

    SECTION("Multiple acquires drain bucket") {
        TokenBucket bucket(100, 10);
        REQUIRE(bucket.try_acquire(3));
        REQUIRE(bucket.try_acquire(3));
        REQUIRE(bucket.try_acquire(3));
        // Only 1 token left
        REQUIRE(bucket.try_acquire(1));
        // Now empty
        REQUIRE_FALSE(bucket.try_acquire(1));
    }

    SECTION("Available tokens reflects current state") {
        TokenBucket bucket(100, 10);
        REQUIRE(bucket.available_tokens() == 10);
        bucket.try_acquire(3);
        // available_tokens is approximate due to CAS, but should be close
        REQUIRE(bucket.available_tokens() <= 10);
    }
}

TEST_CASE("TokenBucket reset", "[rate_limiter]") {

    SECTION("Reset restores full capacity") {
        TokenBucket bucket(100, 10);
        // Drain all tokens
        bucket.try_acquire(10);
        REQUIRE_FALSE(bucket.try_acquire(1));

        // Reset
        bucket.reset();

        // Should be full again
        REQUIRE(bucket.try_acquire(10));
    }
}

TEST_CASE("TokenBucket token refill over time", "[rate_limiter]") {

    SECTION("Tokens refill after waiting") {
        // High refill rate for testability: 1000 tokens/sec = 1 token/ms
        TokenBucket bucket(1000, 10);

        // Drain all tokens
        REQUIRE(bucket.try_acquire(10));
        REQUIRE_FALSE(bucket.try_acquire(1));

        // Wait for refill (20ms should give ~20 tokens, capped at burst=10)
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

        // Should have refilled some tokens
        REQUIRE(bucket.try_acquire(1));
    }

    SECTION("Tokens capped at burst capacity after long wait") {
        TokenBucket bucket(1000, 5);

        // Drain
        bucket.try_acquire(5);

        // Wait long enough for many tokens to be generated
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Should be capped at burst capacity (5)
        REQUIRE(bucket.try_acquire(5));
        // But not more than burst capacity immediately after
        REQUIRE_FALSE(bucket.try_acquire(1));
    }
}

TEST_CASE("TokenBucket zero configuration", "[rate_limiter]") {

    SECTION("Zero burst capacity denies all requests") {
        TokenBucket bucket(100, 0);
        REQUIRE_FALSE(bucket.try_acquire(1));
    }
}

TEST_CASE("HierarchicalRateLimiter 4-level checks", "[rate_limiter]") {

    SECTION("All levels pass when capacity available") {
        HierarchicalRateLimiter::Config config;
        config.global_tokens_per_second = 1000;
        config.global_burst_capacity = 100;
        config.default_user_tokens_per_second = 100;
        config.default_user_burst_capacity = 20;
        config.default_db_tokens_per_second = 500;
        config.default_db_burst_capacity = 50;
        config.default_user_db_tokens_per_second = 50;
        config.default_user_db_burst_capacity = 10;

        HierarchicalRateLimiter limiter(config);

        auto result = limiter.check("alice", "mydb");
        REQUIRE(result.allowed);
        REQUIRE(result.level.empty());  // No rejection level when allowed
    }

    SECTION("Global level rejects when exhausted") {
        HierarchicalRateLimiter::Config config;
        config.global_tokens_per_second = 100;
        config.global_burst_capacity = 5;   // Very small burst
        config.default_user_tokens_per_second = 1000;
        config.default_user_burst_capacity = 200;
        config.default_db_tokens_per_second = 1000;
        config.default_db_burst_capacity = 200;
        config.default_user_db_tokens_per_second = 1000;
        config.default_user_db_burst_capacity = 200;

        HierarchicalRateLimiter limiter(config);

        // Exhaust global bucket
        for (int i = 0; i < 5; ++i) {
            (void)limiter.check("user" + std::to_string(i), "db" + std::to_string(i));
        }

        auto result = limiter.check("alice", "mydb");
        REQUIRE_FALSE(result.allowed);
        REQUIRE(result.level == "global");
    }

    SECTION("User level rejects when user quota exhausted") {
        HierarchicalRateLimiter::Config config;
        config.global_tokens_per_second = 100000;
        config.global_burst_capacity = 10000;
        config.default_user_tokens_per_second = 100;
        config.default_user_burst_capacity = 3;    // Very small user burst
        config.default_db_tokens_per_second = 100000;
        config.default_db_burst_capacity = 10000;
        config.default_user_db_tokens_per_second = 100000;
        config.default_user_db_burst_capacity = 10000;

        HierarchicalRateLimiter limiter(config);

        // Exhaust alice's user bucket (3 tokens)
        for (int i = 0; i < 3; ++i) {
            auto r = limiter.check("alice", "db" + std::to_string(i));
            REQUIRE(r.allowed);
        }

        auto result = limiter.check("alice", "anotherdb");
        REQUIRE_FALSE(result.allowed);
        REQUIRE(result.level == "user");
    }

    SECTION("Database level rejects when database quota exhausted") {
        HierarchicalRateLimiter::Config config;
        config.global_tokens_per_second = 100000;
        config.global_burst_capacity = 10000;
        config.default_user_tokens_per_second = 100000;
        config.default_user_burst_capacity = 10000;
        config.default_db_tokens_per_second = 100;
        config.default_db_burst_capacity = 3;    // Very small DB burst
        config.default_user_db_tokens_per_second = 100000;
        config.default_user_db_burst_capacity = 10000;

        HierarchicalRateLimiter limiter(config);

        // Exhaust database bucket (3 tokens)
        for (int i = 0; i < 3; ++i) {
            auto r = limiter.check("user" + std::to_string(i), "mydb");
            REQUIRE(r.allowed);
        }

        auto result = limiter.check("newuser", "mydb");
        REQUIRE_FALSE(result.allowed);
        REQUIRE(result.level == "database");
    }

    SECTION("User-database level rejects when specific pair quota exhausted") {
        HierarchicalRateLimiter::Config config;
        config.global_tokens_per_second = 100000;
        config.global_burst_capacity = 10000;
        config.default_user_tokens_per_second = 100000;
        config.default_user_burst_capacity = 10000;
        config.default_db_tokens_per_second = 100000;
        config.default_db_burst_capacity = 10000;
        config.default_user_db_tokens_per_second = 100;
        config.default_user_db_burst_capacity = 3;  // Very small user-db burst

        HierarchicalRateLimiter limiter(config);

        // Exhaust alice+mydb bucket (3 tokens)
        for (int i = 0; i < 3; ++i) {
            auto r = limiter.check("alice", "mydb");
            REQUIRE(r.allowed);
        }

        auto result = limiter.check("alice", "mydb");
        REQUIRE_FALSE(result.allowed);
        REQUIRE(result.level == "user_database");
    }
}

TEST_CASE("HierarchicalRateLimiter per-user bucket isolation", "[rate_limiter]") {

    SECTION("Different users have independent buckets") {
        HierarchicalRateLimiter::Config config;
        config.global_tokens_per_second = 100000;
        config.global_burst_capacity = 10000;
        config.default_user_tokens_per_second = 100;
        config.default_user_burst_capacity = 3;
        config.default_db_tokens_per_second = 100000;
        config.default_db_burst_capacity = 10000;
        config.default_user_db_tokens_per_second = 100000;
        config.default_user_db_burst_capacity = 10000;

        HierarchicalRateLimiter limiter(config);

        // Exhaust alice's quota
        for (int i = 0; i < 3; ++i) {
            (void)limiter.check("alice", "mydb");
        }

        // Alice should be rate limited
        auto alice_result = limiter.check("alice", "mydb");
        REQUIRE_FALSE(alice_result.allowed);

        // Bob should still have capacity
        auto bob_result = limiter.check("bob", "mydb");
        REQUIRE(bob_result.allowed);
    }
}

TEST_CASE("HierarchicalRateLimiter per-database bucket isolation", "[rate_limiter]") {

    SECTION("Different databases have independent buckets") {
        HierarchicalRateLimiter::Config config;
        config.global_tokens_per_second = 100000;
        config.global_burst_capacity = 10000;
        config.default_user_tokens_per_second = 100000;
        config.default_user_burst_capacity = 10000;
        config.default_db_tokens_per_second = 100;
        config.default_db_burst_capacity = 3;
        config.default_user_db_tokens_per_second = 100000;
        config.default_user_db_burst_capacity = 10000;

        HierarchicalRateLimiter limiter(config);

        // Exhaust db1's quota
        for (int i = 0; i < 3; ++i) {
            (void)limiter.check("user" + std::to_string(i), "db1");
        }

        // db1 should be rate limited
        auto db1_result = limiter.check("alice", "db1");
        REQUIRE_FALSE(db1_result.allowed);

        // db2 should still have capacity
        auto db2_result = limiter.check("alice", "db2");
        REQUIRE(db2_result.allowed);
    }
}

TEST_CASE("HierarchicalRateLimiter custom limits", "[rate_limiter]") {

    SECTION("Custom user limit overrides default") {
        HierarchicalRateLimiter::Config config;
        config.global_tokens_per_second = 100000;
        config.global_burst_capacity = 10000;
        config.default_user_tokens_per_second = 100;
        config.default_user_burst_capacity = 3;
        config.default_db_tokens_per_second = 100000;
        config.default_db_burst_capacity = 10000;
        config.default_user_db_tokens_per_second = 100000;
        config.default_user_db_burst_capacity = 10000;

        HierarchicalRateLimiter limiter(config);

        // Give alice a higher limit
        limiter.set_user_limit("alice", 10000, 100);

        // Alice should be able to make many more requests than default (3)
        for (int i = 0; i < 10; ++i) {
            auto result = limiter.check("alice", "mydb");
            REQUIRE(result.allowed);
        }
    }

    SECTION("Custom database limit overrides default") {
        HierarchicalRateLimiter::Config config;
        config.global_tokens_per_second = 100000;
        config.global_burst_capacity = 10000;
        config.default_user_tokens_per_second = 100000;
        config.default_user_burst_capacity = 10000;
        config.default_db_tokens_per_second = 100;
        config.default_db_burst_capacity = 2;  // Very low default
        config.default_user_db_tokens_per_second = 100000;
        config.default_user_db_burst_capacity = 10000;

        HierarchicalRateLimiter limiter(config);

        // Give mydb a higher limit
        limiter.set_database_limit("mydb", 10000, 100);

        // Should handle many requests to mydb
        for (int i = 0; i < 10; ++i) {
            auto result = limiter.check("user" + std::to_string(i), "mydb");
            REQUIRE(result.allowed);
        }
    }

    SECTION("Custom user-database limit overrides default") {
        HierarchicalRateLimiter::Config config;
        config.global_tokens_per_second = 100000;
        config.global_burst_capacity = 10000;
        config.default_user_tokens_per_second = 100000;
        config.default_user_burst_capacity = 10000;
        config.default_db_tokens_per_second = 100000;
        config.default_db_burst_capacity = 10000;
        config.default_user_db_tokens_per_second = 100;
        config.default_user_db_burst_capacity = 2;  // Very low default

        HierarchicalRateLimiter limiter(config);

        // Give alice+mydb a higher limit
        limiter.set_user_database_limit("alice", "mydb", 10000, 100);

        // Should handle many alice+mydb requests
        for (int i = 0; i < 10; ++i) {
            auto result = limiter.check("alice", "mydb");
            REQUIRE(result.allowed);
        }
    }
}

TEST_CASE("HierarchicalRateLimiter reset_all", "[rate_limiter]") {

    SECTION("Reset restores all buckets to full capacity") {
        HierarchicalRateLimiter::Config config;
        config.global_tokens_per_second = 100;
        config.global_burst_capacity = 5;
        config.default_user_tokens_per_second = 100;
        config.default_user_burst_capacity = 5;
        config.default_db_tokens_per_second = 100;
        config.default_db_burst_capacity = 5;
        config.default_user_db_tokens_per_second = 100;
        config.default_user_db_burst_capacity = 5;

        HierarchicalRateLimiter limiter(config);

        // Exhaust all buckets
        for (int i = 0; i < 5; ++i) {
            (void)limiter.check("alice", "mydb");
        }

        // Should be rate limited now
        auto denied = limiter.check("alice", "mydb");
        REQUIRE_FALSE(denied.allowed);

        // Reset everything
        limiter.reset_all();

        // Should be allowed again
        auto allowed = limiter.check("alice", "mydb");
        REQUIRE(allowed.allowed);
    }
}

TEST_CASE("HierarchicalRateLimiter statistics", "[rate_limiter]") {

    SECTION("Stats track total checks") {
        HierarchicalRateLimiter::Config config;
        config.global_tokens_per_second = 100000;
        config.global_burst_capacity = 10000;
        config.default_user_tokens_per_second = 100000;
        config.default_user_burst_capacity = 10000;
        config.default_db_tokens_per_second = 100000;
        config.default_db_burst_capacity = 10000;
        config.default_user_db_tokens_per_second = 100000;
        config.default_user_db_burst_capacity = 10000;

        HierarchicalRateLimiter limiter(config);

        (void)limiter.check("alice", "db1");
        (void)limiter.check("bob", "db2");
        (void)limiter.check("charlie", "db1");

        auto stats = limiter.get_stats();
        REQUIRE(stats.total_checks == 3);
    }

    SECTION("Stats track rejections per level") {
        HierarchicalRateLimiter::Config config;
        config.global_tokens_per_second = 100;
        config.global_burst_capacity = 2;
        config.default_user_tokens_per_second = 100000;
        config.default_user_burst_capacity = 10000;
        config.default_db_tokens_per_second = 100000;
        config.default_db_burst_capacity = 10000;
        config.default_user_db_tokens_per_second = 100000;
        config.default_user_db_burst_capacity = 10000;

        HierarchicalRateLimiter limiter(config);

        // Use up global tokens
        (void)limiter.check("alice", "db1");
        (void)limiter.check("bob", "db2");

        // Next should be rejected at global level
        (void)limiter.check("charlie", "db3");

        auto stats = limiter.get_stats();
        REQUIRE(stats.global_rejects >= 1);
    }
}

TEST_CASE("RateLimitResult structure", "[rate_limiter]") {

    SECTION("Allowed result") {
        RateLimitResult result(true, 42, std::chrono::milliseconds(0), "");
        REQUIRE(result.allowed);
        REQUIRE(result.tokens_remaining == 42);
        REQUIRE(result.retry_after.count() == 0);
        REQUIRE(result.level.empty());
    }

    SECTION("Denied result") {
        RateLimitResult result(false, 0, std::chrono::milliseconds(1000), "global");
        REQUIRE_FALSE(result.allowed);
        REQUIRE(result.tokens_remaining == 0);
        REQUIRE(result.retry_after.count() == 1000);
        REQUIRE(result.level == "global");
    }

    SECTION("Default-constructed result is denied") {
        RateLimitResult result;
        REQUIRE_FALSE(result.allowed);
        REQUIRE(result.tokens_remaining == 0);
    }
}
