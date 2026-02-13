#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace sqlproxy {

// Transaction states (explicit state machine)
enum class TxnState : uint8_t {
    IDLE,
    ACTIVE,
    PREPARING,
    PREPARED,
    COMMITTING,
    COMMITTED,
    ABORTING,
    ABORTED
};

[[nodiscard]] inline const char* txn_state_to_string(TxnState s) {
    switch (s) {
        case TxnState::IDLE:       return "IDLE";
        case TxnState::ACTIVE:     return "ACTIVE";
        case TxnState::PREPARING:  return "PREPARING";
        case TxnState::PREPARED:   return "PREPARED";
        case TxnState::COMMITTING: return "COMMITTING";
        case TxnState::COMMITTED:  return "COMMITTED";
        case TxnState::ABORTING:   return "ABORTING";
        case TxnState::ABORTED:    return "ABORTED";
        default:                   return "UNKNOWN";
    }
}

// A participant in a distributed transaction
struct TxnParticipant {
    std::string database;
    TxnState local_state = TxnState::IDLE;
    std::chrono::steady_clock::time_point joined_at;
};

// Distributed transaction record
struct DistributedTransaction {
    std::string xid;
    std::string user;
    TxnState state = TxnState::IDLE;
    std::vector<TxnParticipant> participants;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point last_activity;
};

/**
 * @brief Two-Phase Commit (2PC) transaction coordinator.
 *
 * Manages distributed transactions across multiple databases:
 * - State machine: IDLE → ACTIVE → PREPARING → PREPARED → COMMITTING → COMMITTED
 *                                                        → ABORTING → ABORTED
 * - Background thread timeouts stale transactions
 * - PostgreSQL-compatible XID generation
 */
class TransactionCoordinator {
public:
    struct Config {
        bool enabled = false;
        uint32_t timeout_ms = 30000;
        uint32_t max_active_transactions = 100;
        uint32_t cleanup_interval_seconds = 60;
    };

    TransactionCoordinator();
    explicit TransactionCoordinator(Config config);
    ~TransactionCoordinator();

    [[nodiscard]] bool is_enabled() const { return config_.enabled; }

    // Transaction lifecycle
    [[nodiscard]] std::string begin_transaction(const std::string& user);
    [[nodiscard]] bool enlist_participant(const std::string& xid,
                                         const std::string& database);
    [[nodiscard]] bool prepare(const std::string& xid);
    [[nodiscard]] bool commit(const std::string& xid);
    [[nodiscard]] bool rollback(const std::string& xid);

    // Query state
    [[nodiscard]] std::optional<DistributedTransaction> get_transaction(
        const std::string& xid) const;
    [[nodiscard]] std::vector<DistributedTransaction> active_transactions() const;

    // Background cleanup
    void start_cleanup();
    void stop_cleanup();

    // Generate PostgreSQL-compatible XID
    [[nodiscard]] static std::string generate_xid();

    // State validation
    [[nodiscard]] static bool is_valid_transition(TxnState from, TxnState to);

    struct Stats {
        uint64_t transactions_started = 0;
        uint64_t transactions_committed = 0;
        uint64_t transactions_aborted = 0;
        uint64_t transactions_timed_out = 0;
        size_t active_count = 0;
    };

    [[nodiscard]] Stats get_stats() const;

private:
    void cleanup_loop();
    void timeout_stale_transactions();

    Config config_;

    std::unordered_map<std::string, DistributedTransaction> transactions_;
    mutable std::shared_mutex txn_mutex_;

    // Background cleanup
    std::thread cleanup_thread_;
    std::atomic<bool> running_{false};
    std::mutex cleanup_mutex_;
    std::condition_variable cleanup_cv_;

    // Stats
    std::atomic<uint64_t> started_{0};
    std::atomic<uint64_t> committed_{0};
    std::atomic<uint64_t> aborted_{0};
    std::atomic<uint64_t> timed_out_{0};
};

} // namespace sqlproxy
