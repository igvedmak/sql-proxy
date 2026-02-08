#include <catch2/catch_test_macros.hpp>
#include "security/lineage_tracker.hpp"

using namespace sqlproxy;

static LineageEvent make_event(const std::string& user, const std::string& table,
                               const std::string& column, const std::string& classification,
                               bool was_masked = false) {
    LineageEvent e;
    e.timestamp = "2026-01-01T00:00:00.000Z";
    e.user = user;
    e.database = "testdb";
    e.table = table;
    e.column = column;
    e.classification = classification;
    e.access_type = "SELECT";
    e.was_masked = was_masked;
    e.masking_action = was_masked ? "PARTIAL" : "";
    return e;
}

// ============================================================================
// Basic recording
// ============================================================================

TEST_CASE("Record events and count them", "[lineage]") {
    LineageTracker tracker;
    CHECK(tracker.total_events() == 0);

    tracker.record(make_event("alice", "customers", "email", "PII.Email"));
    CHECK(tracker.total_events() == 1);

    tracker.record(make_event("bob", "customers", "phone", "PII.Phone"));
    CHECK(tracker.total_events() == 2);
}

// ============================================================================
// Summaries
// ============================================================================

TEST_CASE("Summaries aggregate correctly", "[lineage]") {
    LineageTracker tracker;

    tracker.record(make_event("alice", "customers", "email", "PII.Email", false));
    tracker.record(make_event("bob", "customers", "email", "PII.Email", true));
    tracker.record(make_event("alice", "customers", "email", "PII.Email", true));

    auto summaries = tracker.get_summaries();
    REQUIRE(summaries.size() == 1);

    const auto& s = summaries[0];
    CHECK(s.total_accesses == 3);
    CHECK(s.masked_accesses == 2);
    CHECK(s.unmasked_accesses == 1);
    CHECK(s.accessing_users.size() == 2);
    CHECK(s.accessing_users.contains("alice"));
    CHECK(s.accessing_users.contains("bob"));
}

// ============================================================================
// Multiple columns
// ============================================================================

TEST_CASE("Multiple columns tracked independently", "[lineage]") {
    LineageTracker tracker;

    tracker.record(make_event("alice", "customers", "email", "PII.Email"));
    tracker.record(make_event("alice", "customers", "phone", "PII.Phone"));
    tracker.record(make_event("alice", "sensitive_data", "ssn", "PII.SSN"));

    auto summaries = tracker.get_summaries();
    CHECK(summaries.size() == 3);
}

// ============================================================================
// Event retrieval
// ============================================================================

TEST_CASE("Get events returns most recent first", "[lineage]") {
    LineageTracker tracker;

    tracker.record(make_event("alice", "customers", "email", "PII.Email"));
    tracker.record(make_event("bob", "orders", "total", "Sensitive.Financial"));
    tracker.record(make_event("charlie", "customers", "phone", "PII.Phone"));

    auto events = tracker.get_events("", "", 10);
    REQUIRE(events.size() == 3);
    // Most recent first
    CHECK(events[0].user == "charlie");
    CHECK(events[2].user == "alice");
}

TEST_CASE("Get events filtered by user", "[lineage]") {
    LineageTracker tracker;

    tracker.record(make_event("alice", "customers", "email", "PII.Email"));
    tracker.record(make_event("bob", "orders", "total", "Sensitive.Financial"));
    tracker.record(make_event("alice", "customers", "phone", "PII.Phone"));

    auto events = tracker.get_events("alice", "", 10);
    REQUIRE(events.size() == 2);
    CHECK(events[0].user == "alice");
    CHECK(events[1].user == "alice");
}

TEST_CASE("Get events filtered by table", "[lineage]") {
    LineageTracker tracker;

    tracker.record(make_event("alice", "customers", "email", "PII.Email"));
    tracker.record(make_event("bob", "orders", "total", "Sensitive.Financial"));

    auto events = tracker.get_events("", "orders", 10);
    REQUIRE(events.size() == 1);
    CHECK(events[0].table == "orders");
}

// ============================================================================
// Capacity limit
// ============================================================================

TEST_CASE("Events capped at max capacity", "[lineage]") {
    LineageTracker::Config cfg;
    cfg.max_events = 5;
    LineageTracker tracker(cfg);

    for (int i = 0; i < 10; ++i) {
        tracker.record(make_event("user" + std::to_string(i), "t", "c", "PII"));
    }

    CHECK(tracker.total_events() == 5);
    auto events = tracker.get_events("", "", 100);
    CHECK(events.size() == 5);
}

// ============================================================================
// Disabled tracker
// ============================================================================

TEST_CASE("Disabled tracker does not record", "[lineage]") {
    LineageTracker::Config cfg;
    cfg.enabled = false;
    LineageTracker tracker(cfg);

    tracker.record(make_event("alice", "customers", "email", "PII.Email"));
    CHECK(tracker.total_events() == 0);
}
