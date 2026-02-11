#include <catch2/catch_test_macros.hpp>
#include "security/column_version_tracker.hpp"

using namespace sqlproxy;

TEST_CASE("ColumnVersionTracker - disabled", "[column_versioning]") {
    ColumnVersionTracker tracker;
    REQUIRE_FALSE(tracker.is_enabled());

    ColumnVersionEvent event;
    event.table = "customers";
    event.column = "email";
    event.operation = "UPDATE";
    tracker.record(event);

    REQUIRE(tracker.total_events() == 0);
}

TEST_CASE("ColumnVersionTracker - record and retrieve", "[column_versioning]") {
    ColumnVersionTracker::Config cfg;
    cfg.enabled = true;
    cfg.max_events = 100;
    ColumnVersionTracker tracker(cfg);

    ColumnVersionEvent e1;
    e1.timestamp = "2024-01-01T00:00:00Z";
    e1.user = "admin";
    e1.database = "testdb";
    e1.table = "customers";
    e1.column = "email";
    e1.operation = "UPDATE";
    e1.affected_rows = 5;
    tracker.record(e1);

    ColumnVersionEvent e2;
    e2.timestamp = "2024-01-01T00:01:00Z";
    e2.user = "admin";
    e2.database = "testdb";
    e2.table = "orders";
    e2.column = "total";
    e2.operation = "INSERT";
    e2.affected_rows = 10;
    tracker.record(e2);

    REQUIRE(tracker.total_events() == 2);

    auto all = tracker.get_history();
    REQUIRE(all.size() == 2);
    // Newest first
    REQUIRE(all[0].table == "orders");
    REQUIRE(all[1].table == "customers");
}

TEST_CASE("ColumnVersionTracker - filter by table", "[column_versioning]") {
    ColumnVersionTracker::Config cfg;
    cfg.enabled = true;
    ColumnVersionTracker tracker(cfg);

    ColumnVersionEvent e1;
    e1.table = "customers";
    e1.column = "email";
    e1.operation = "UPDATE";
    tracker.record(e1);

    ColumnVersionEvent e2;
    e2.table = "orders";
    e2.column = "total";
    e2.operation = "INSERT";
    tracker.record(e2);

    auto filtered = tracker.get_history("customers");
    REQUIRE(filtered.size() == 1);
    REQUIRE(filtered[0].table == "customers");
}

TEST_CASE("ColumnVersionTracker - filter by column", "[column_versioning]") {
    ColumnVersionTracker::Config cfg;
    cfg.enabled = true;
    ColumnVersionTracker tracker(cfg);

    ColumnVersionEvent e1;
    e1.table = "customers";
    e1.column = "email";
    e1.operation = "UPDATE";
    tracker.record(e1);

    ColumnVersionEvent e2;
    e2.table = "customers";
    e2.column = "name";
    e2.operation = "UPDATE";
    tracker.record(e2);

    auto filtered = tracker.get_history("customers", "email");
    REQUIRE(filtered.size() == 1);
    REQUIRE(filtered[0].column == "email");
}

TEST_CASE("ColumnVersionTracker - max events eviction", "[column_versioning]") {
    ColumnVersionTracker::Config cfg;
    cfg.enabled = true;
    cfg.max_events = 3;
    ColumnVersionTracker tracker(cfg);

    for (int i = 0; i < 5; ++i) {
        ColumnVersionEvent e;
        e.table = "t" + std::to_string(i);
        e.column = "c";
        e.operation = "INSERT";
        tracker.record(e);
    }

    REQUIRE(tracker.total_events() == 3);
    auto all = tracker.get_history();
    // Oldest events evicted; newest = t4, t3, t2
    REQUIRE(all[0].table == "t4");
    REQUIRE(all[1].table == "t3");
    REQUIRE(all[2].table == "t2");
}

TEST_CASE("ColumnVersionTracker - limit parameter", "[column_versioning]") {
    ColumnVersionTracker::Config cfg;
    cfg.enabled = true;
    ColumnVersionTracker tracker(cfg);

    for (int i = 0; i < 10; ++i) {
        ColumnVersionEvent e;
        e.table = "t";
        e.column = "c";
        e.operation = "UPDATE";
        tracker.record(e);
    }

    auto limited = tracker.get_history("", "", 3);
    REQUIRE(limited.size() == 3);
}
