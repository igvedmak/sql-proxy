#include <catch2/catch_test_macros.hpp>
#include "cache/result_cache.hpp"
#include "config/config_loader.hpp"

#include <chrono>
#include <thread>

using namespace sqlproxy;

static QueryResult make_result(const std::vector<std::string>& cols,
                               const std::vector<std::vector<std::string>>& rows) {
    QueryResult r;
    r.success = true;
    r.error_code = ErrorCode::NONE;
    r.column_names = cols;
    r.rows = rows;
    r.affected_rows = 0;
    return r;
}

TEST_CASE("ResultCache: disabled returns nullopt", "[cache]") {
    ResultCache::Config cfg;
    cfg.enabled = false;
    ResultCache cache(cfg);

    auto result = cache.get(12345, "user", "testdb");
    CHECK_FALSE(result.has_value());
    CHECK_FALSE(cache.is_enabled());
}

TEST_CASE("ResultCache: put then get returns same result", "[cache]") {
    ResultCache::Config cfg;
    cfg.enabled = true;
    cfg.max_entries = 100;
    cfg.num_shards = 4;
    cfg.ttl = std::chrono::seconds(60);
    ResultCache cache(cfg);

    auto original = make_result({"id", "name"}, {{"1", "Alice"}, {"2", "Bob"}});
    cache.put(42, "analyst", "testdb", original);

    auto cached = cache.get(42, "analyst", "testdb");
    REQUIRE(cached.has_value());
    CHECK(cached->column_names == original.column_names);
    CHECK(cached->rows == original.rows);
}

TEST_CASE("ResultCache: miss returns nullopt", "[cache]") {
    ResultCache::Config cfg;
    cfg.enabled = true;
    cfg.max_entries = 100;
    cfg.num_shards = 4;
    cfg.ttl = std::chrono::seconds(60);
    ResultCache cache(cfg);

    auto result = cache.get(99999, "user", "testdb");
    CHECK_FALSE(result.has_value());

    auto stats = cache.get_stats();
    CHECK(stats.misses == 1);
    CHECK(stats.hits == 0);
}

TEST_CASE("ResultCache: TTL expiry", "[cache]") {
    ResultCache::Config cfg;
    cfg.enabled = true;
    cfg.max_entries = 100;
    cfg.num_shards = 1;
    cfg.ttl = std::chrono::seconds(0);  // Expire immediately
    ResultCache cache(cfg);

    auto original = make_result({"id"}, {{"1"}});
    cache.put(42, "user", "testdb", original);

    // Wait a bit to ensure expiry
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    auto cached = cache.get(42, "user", "testdb");
    CHECK_FALSE(cached.has_value());
}

TEST_CASE("ResultCache: invalidate clears database entries", "[cache]") {
    ResultCache::Config cfg;
    cfg.enabled = true;
    cfg.max_entries = 100;
    cfg.num_shards = 4;
    cfg.ttl = std::chrono::seconds(60);
    ResultCache cache(cfg);

    auto r1 = make_result({"a"}, {{"1"}});
    auto r2 = make_result({"b"}, {{"2"}});
    cache.put(1, "user", "db1", r1);
    cache.put(2, "user", "db2", r2);

    cache.invalidate("db1");

    CHECK_FALSE(cache.get(1, "user", "db1").has_value());
    CHECK(cache.get(2, "user", "db2").has_value());  // db2 unaffected

    auto stats = cache.get_stats();
    CHECK(stats.invalidations == 1);
}

TEST_CASE("ResultCache: LRU eviction at capacity", "[cache]") {
    ResultCache::Config cfg;
    cfg.enabled = true;
    cfg.max_entries = 2;  // Only 2 entries total
    cfg.num_shards = 1;   // Single shard for deterministic testing
    cfg.ttl = std::chrono::seconds(60);
    ResultCache cache(cfg);

    auto r = make_result({"x"}, {{"val"}});
    cache.put(1, "user", "db", r);
    cache.put(2, "user", "db", r);
    cache.put(3, "user", "db", r);  // Should evict entry 1 (LRU)

    CHECK_FALSE(cache.get(1, "user", "db").has_value());  // Evicted
    CHECK(cache.get(2, "user", "db").has_value());
    CHECK(cache.get(3, "user", "db").has_value());

    auto stats = cache.get_stats();
    CHECK(stats.evictions >= 1);
}

TEST_CASE("ResultCache: oversized result not cached", "[cache]") {
    ResultCache::Config cfg;
    cfg.enabled = true;
    cfg.max_entries = 100;
    cfg.num_shards = 1;
    cfg.ttl = std::chrono::seconds(60);
    cfg.max_result_size_bytes = 50;  // Very small limit
    ResultCache cache(cfg);

    // Create a large result
    auto big_result = make_result({"data"}, {{std::string(100, 'X')}});
    cache.put(42, "user", "db", big_result);

    CHECK_FALSE(cache.get(42, "user", "db").has_value());
}

TEST_CASE("ResultCache: different users get separate entries", "[cache]") {
    ResultCache::Config cfg;
    cfg.enabled = true;
    cfg.max_entries = 100;
    cfg.num_shards = 4;
    cfg.ttl = std::chrono::seconds(60);
    ResultCache cache(cfg);

    auto r1 = make_result({"name"}, {{"Alice"}});
    auto r2 = make_result({"name"}, {{"Bob"}});

    cache.put(42, "user_a", "testdb", r1);
    cache.put(42, "user_b", "testdb", r2);

    auto cached_a = cache.get(42, "user_a", "testdb");
    auto cached_b = cache.get(42, "user_b", "testdb");

    REQUIRE(cached_a.has_value());
    REQUIRE(cached_b.has_value());
    CHECK(cached_a->rows[0][0] == "Alice");
    CHECK(cached_b->rows[0][0] == "Bob");
}

TEST_CASE("ResultCache: stats tracking", "[cache]") {
    ResultCache::Config cfg;
    cfg.enabled = true;
    cfg.max_entries = 100;
    cfg.num_shards = 4;
    cfg.ttl = std::chrono::seconds(60);
    ResultCache cache(cfg);

    auto r = make_result({"id"}, {{"1"}});
    cache.put(42, "user", "db", r);

    cache.get(42, "user", "db");  // hit
    cache.get(99, "user", "db");  // miss

    auto stats = cache.get_stats();
    CHECK(stats.hits == 1);
    CHECK(stats.misses == 1);
    CHECK(stats.current_entries == 1);
}

TEST_CASE("ResultCache: config from TOML", "[cache][config]") {
    std::string toml = R"(
[result_cache]
enabled = true
max_entries = 10000
num_shards = 32
ttl_seconds = 120
max_result_size_bytes = 2097152
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    REQUIRE(result.config.result_cache.enabled);
    REQUIRE(result.config.result_cache.max_entries == 10000);
    REQUIRE(result.config.result_cache.num_shards == 32);
    REQUIRE(result.config.result_cache.ttl_seconds == 120);
    REQUIRE(result.config.result_cache.max_result_size_bytes == 2097152);
}
