#include <catch2/catch_test_macros.hpp>
#include "core/slow_query_tracker.hpp"
#include "config/config_loader.hpp"

using namespace sqlproxy;

static SlowQueryRecord make_record(const std::string& user, const std::string& db,
                                    std::chrono::microseconds exec_time) {
    SlowQueryRecord r;
    r.user = user;
    r.database = db;
    r.sql = "SELECT 1";
    r.execution_time = exec_time;
    r.statement_type = StatementType::SELECT;
    return r;
}

TEST_CASE("SlowQueryTracker: fast query not recorded", "[slow_query]") {
    SlowQueryTracker::Config cfg;
    cfg.enabled = true;
    cfg.threshold_ms = 100;
    SlowQueryTracker tracker(cfg);

    auto fast = make_record("user", "db", std::chrono::microseconds(50000)); // 50ms
    CHECK_FALSE(tracker.record_if_slow(fast));
    CHECK(tracker.total_slow_queries() == 0);
    CHECK(tracker.get_recent().empty());
}

TEST_CASE("SlowQueryTracker: slow query recorded", "[slow_query]") {
    SlowQueryTracker::Config cfg;
    cfg.enabled = true;
    cfg.threshold_ms = 100;
    SlowQueryTracker tracker(cfg);

    auto slow = make_record("analyst", "proddb", std::chrono::microseconds(200000)); // 200ms
    CHECK(tracker.record_if_slow(slow));
    CHECK(tracker.total_slow_queries() == 1);

    auto recent = tracker.get_recent();
    REQUIRE(recent.size() == 1);
    CHECK(recent[0].user == "analyst");
    CHECK(recent[0].database == "proddb");
    CHECK(recent[0].execution_time == std::chrono::microseconds(200000));
}

TEST_CASE("SlowQueryTracker: circular buffer respects max_entries", "[slow_query]") {
    SlowQueryTracker::Config cfg;
    cfg.enabled = true;
    cfg.threshold_ms = 10;
    cfg.max_entries = 5;
    SlowQueryTracker tracker(cfg);

    // Add 10 slow queries (threshold=10ms, all are >=10ms)
    for (int i = 0; i < 10; ++i) {
        auto r = make_record("user" + std::to_string(i), "db",
                             std::chrono::microseconds(20000)); // 20ms
        tracker.record_if_slow(r);
    }

    CHECK(tracker.total_slow_queries() == 10);
    auto recent = tracker.get_recent();
    CHECK(recent.size() == 5);  // Only last 5 kept

    // Verify the oldest entries were evicted (user0-4 gone, user5-9 remain)
    CHECK(recent[0].user == "user5");
    CHECK(recent[4].user == "user9");
}

TEST_CASE("SlowQueryTracker: disabled tracker does nothing", "[slow_query]") {
    SlowQueryTracker::Config cfg;
    cfg.enabled = false;
    cfg.threshold_ms = 1;
    SlowQueryTracker tracker(cfg);

    auto slow = make_record("user", "db", std::chrono::microseconds(1000000)); // 1 second
    CHECK_FALSE(tracker.record_if_slow(slow));
    CHECK(tracker.total_slow_queries() == 0);
    CHECK_FALSE(tracker.is_enabled());
}

TEST_CASE("SlowQueryTracker: TOML config parsing", "[slow_query][config]") {
    const std::string toml = R"(
[server]
port = 8080

[slow_query]
enabled = true
threshold_ms = 250
max_entries = 500
)";
    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    CHECK(result.config.slow_query.enabled == true);
    CHECK(result.config.slow_query.threshold_ms == 250);
    CHECK(result.config.slow_query.max_entries == 500);
}

TEST_CASE("SlowQueryTracker: get_recent with limit", "[slow_query]") {
    SlowQueryTracker::Config cfg;
    cfg.enabled = true;
    cfg.threshold_ms = 10;
    cfg.max_entries = 100;
    SlowQueryTracker tracker(cfg);

    for (int i = 0; i < 20; ++i) {
        auto r = make_record("user", "db", std::chrono::microseconds(50000));
        tracker.record_if_slow(r);
    }

    auto limited = tracker.get_recent(5);
    CHECK(limited.size() == 5);

    auto all = tracker.get_recent(0);
    CHECK(all.size() == 20);
}
