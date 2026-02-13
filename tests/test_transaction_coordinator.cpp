#include <catch2/catch_test_macros.hpp>
#include "core/transaction_coordinator.hpp"
#include <thread>
#include <chrono>
#include <unordered_set>

using namespace sqlproxy;

static TransactionCoordinator::Config enabled_config() {
    TransactionCoordinator::Config cfg;
    cfg.enabled = true;
    cfg.timeout_ms = 5000;
    cfg.max_active_transactions = 10;
    cfg.cleanup_interval_seconds = 1;
    return cfg;
}

TEST_CASE("TransactionCoordinator", "[transaction_coordinator]") {

    SECTION("Disabled returns empty/false") {
        TransactionCoordinator tc;
        REQUIRE_FALSE(tc.is_enabled());
        REQUIRE(tc.begin_transaction("user1").empty());
        REQUIRE_FALSE(tc.enlist_participant("xid", "db1"));
        REQUIRE_FALSE(tc.prepare("xid"));
        REQUIRE_FALSE(tc.commit("xid"));
        REQUIRE_FALSE(tc.rollback("xid"));
    }

    SECTION("Begin transaction") {
        TransactionCoordinator tc(enabled_config());
        auto xid = tc.begin_transaction("user1");
        REQUIRE_FALSE(xid.empty());
        REQUIRE(xid.starts_with("sqlproxy_"));

        auto txn = tc.get_transaction(xid);
        REQUIRE(txn.has_value());
        REQUIRE(txn->state == TxnState::ACTIVE);
        REQUIRE(txn->user == "user1");
        REQUIRE(txn->participants.empty());
    }

    SECTION("Enlist participant") {
        TransactionCoordinator tc(enabled_config());
        auto xid = tc.begin_transaction("user1");

        REQUIRE(tc.enlist_participant(xid, "db1"));
        REQUIRE(tc.enlist_participant(xid, "db2"));

        // Duplicate is OK
        REQUIRE(tc.enlist_participant(xid, "db1"));

        auto txn = tc.get_transaction(xid);
        REQUIRE(txn->participants.size() == 2);
        REQUIRE(txn->participants[0].database == "db1");
        REQUIRE(txn->participants[1].database == "db2");
    }

    SECTION("Full 2PC happy path: begin → enlist → prepare → commit") {
        TransactionCoordinator tc(enabled_config());
        auto xid = tc.begin_transaction("user1");

        REQUIRE(tc.enlist_participant(xid, "db1"));
        REQUIRE(tc.enlist_participant(xid, "db2"));

        REQUIRE(tc.prepare(xid));
        auto txn = tc.get_transaction(xid);
        REQUIRE(txn->state == TxnState::PREPARED);
        for (const auto& p : txn->participants) {
            REQUIRE(p.local_state == TxnState::PREPARED);
        }

        REQUIRE(tc.commit(xid));
        txn = tc.get_transaction(xid);
        REQUIRE(txn->state == TxnState::COMMITTED);
        for (const auto& p : txn->participants) {
            REQUIRE(p.local_state == TxnState::COMMITTED);
        }

        auto stats = tc.get_stats();
        REQUIRE(stats.transactions_started == 1);
        REQUIRE(stats.transactions_committed == 1);
        REQUIRE(stats.transactions_aborted == 0);
    }

    SECTION("Rollback after prepare") {
        TransactionCoordinator tc(enabled_config());
        auto xid = tc.begin_transaction("user1");
        (void)tc.enlist_participant(xid, "db1");
        (void)tc.prepare(xid);

        REQUIRE(tc.rollback(xid));
        auto txn = tc.get_transaction(xid);
        REQUIRE(txn->state == TxnState::ABORTED);
        for (const auto& p : txn->participants) {
            REQUIRE(p.local_state == TxnState::ABORTED);
        }

        auto stats = tc.get_stats();
        REQUIRE(stats.transactions_aborted == 1);
    }

    SECTION("Invalid state transitions") {
        TransactionCoordinator tc(enabled_config());
        auto xid = tc.begin_transaction("user1");

        // Cannot commit from ACTIVE (must prepare first)
        REQUIRE_FALSE(tc.commit(xid));

        // Cannot prepare without participants
        REQUIRE_FALSE(tc.prepare(xid));

        (void)tc.enlist_participant(xid, "db1");
        (void)tc.prepare(xid);
        (void)tc.commit(xid);

        // Cannot rollback from COMMITTED
        REQUIRE_FALSE(tc.rollback(xid));

        // Cannot prepare from COMMITTED
        REQUIRE_FALSE(tc.prepare(xid));
    }

    SECTION("State transition validation") {
        // Valid transitions
        REQUIRE(TransactionCoordinator::is_valid_transition(TxnState::IDLE, TxnState::ACTIVE));
        REQUIRE(TransactionCoordinator::is_valid_transition(TxnState::ACTIVE, TxnState::PREPARING));
        REQUIRE(TransactionCoordinator::is_valid_transition(TxnState::ACTIVE, TxnState::ABORTING));
        REQUIRE(TransactionCoordinator::is_valid_transition(TxnState::PREPARED, TxnState::COMMITTING));
        REQUIRE(TransactionCoordinator::is_valid_transition(TxnState::PREPARED, TxnState::ABORTING));

        // Invalid transitions
        REQUIRE_FALSE(TransactionCoordinator::is_valid_transition(TxnState::COMMITTED, TxnState::ABORTING));
        REQUIRE_FALSE(TransactionCoordinator::is_valid_transition(TxnState::ABORTED, TxnState::ACTIVE));
        REQUIRE_FALSE(TransactionCoordinator::is_valid_transition(TxnState::IDLE, TxnState::COMMITTED));
    }

    SECTION("Max active transactions limit") {
        auto cfg = enabled_config();
        cfg.max_active_transactions = 3;
        TransactionCoordinator tc(cfg);

        auto xid1 = tc.begin_transaction("u1");
        auto xid2 = tc.begin_transaction("u2");
        auto xid3 = tc.begin_transaction("u3");
        REQUIRE_FALSE(xid1.empty());
        REQUIRE_FALSE(xid2.empty());
        REQUIRE_FALSE(xid3.empty());

        // 4th should fail
        auto xid4 = tc.begin_transaction("u4");
        REQUIRE(xid4.empty());
    }

    SECTION("Transaction timeout") {
        auto cfg = enabled_config();
        cfg.timeout_ms = 50;      // 50ms timeout for fast test
        cfg.cleanup_interval_seconds = 1;
        TransactionCoordinator tc(cfg);

        auto xid = tc.begin_transaction("user1");
        (void)tc.enlist_participant(xid, "db1");

        // Wait for timeout
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Trigger cleanup manually by starting/stopping
        tc.start_cleanup();
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        tc.stop_cleanup();

        auto txn = tc.get_transaction(xid);
        REQUIRE(txn.has_value());
        REQUIRE(txn->state == TxnState::ABORTED);

        auto stats = tc.get_stats();
        REQUIRE(stats.transactions_timed_out >= 1);
    }

    SECTION("XID generation is unique") {
        std::unordered_set<std::string> xids;
        for (int i = 0; i < 100; ++i) {
            auto xid = TransactionCoordinator::generate_xid();
            REQUIRE(xid.starts_with("sqlproxy_"));
            REQUIRE(xids.insert(xid).second); // Must be unique
        }
    }

    SECTION("Active transactions list") {
        TransactionCoordinator tc(enabled_config());
        auto xid1 = tc.begin_transaction("u1");
        auto xid2 = tc.begin_transaction("u2");
        (void)tc.enlist_participant(xid2, "db1");
        (void)tc.prepare(xid2);
        (void)tc.commit(xid2);

        auto active = tc.active_transactions();
        REQUIRE(active.size() == 1); // Only xid1 is still active
        REQUIRE(active[0].xid == xid1);
    }

    SECTION("Enlist on non-existent transaction fails") {
        TransactionCoordinator tc(enabled_config());
        REQUIRE_FALSE(tc.enlist_participant("bogus_xid", "db1"));
    }

    SECTION("Get non-existent transaction returns nullopt") {
        TransactionCoordinator tc(enabled_config());
        REQUIRE_FALSE(tc.get_transaction("bogus_xid").has_value());
    }
}
