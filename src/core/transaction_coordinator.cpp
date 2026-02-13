#include "core/transaction_coordinator.hpp"
#include "core/utils.hpp"
#include <format>

namespace sqlproxy {

// ============================================================================
// Construction / Destruction
// ============================================================================

TransactionCoordinator::TransactionCoordinator() = default;

TransactionCoordinator::TransactionCoordinator(Config config)
    : config_(config) {}

TransactionCoordinator::~TransactionCoordinator() {
    stop_cleanup();
}

// ============================================================================
// State Validation
// ============================================================================

bool TransactionCoordinator::is_valid_transition(TxnState from, TxnState to) {
    switch (from) {
        case TxnState::IDLE:
            return to == TxnState::ACTIVE;
        case TxnState::ACTIVE:
            return to == TxnState::PREPARING || to == TxnState::ABORTING;
        case TxnState::PREPARING:
            return to == TxnState::PREPARED || to == TxnState::ABORTING;
        case TxnState::PREPARED:
            return to == TxnState::COMMITTING || to == TxnState::ABORTING;
        case TxnState::COMMITTING:
            return to == TxnState::COMMITTED;
        case TxnState::ABORTING:
            return to == TxnState::ABORTED;
        case TxnState::COMMITTED:
        case TxnState::ABORTED:
            return false; // Terminal states
        default:
            return false;
    }
}

// ============================================================================
// Transaction Lifecycle
// ============================================================================

std::string TransactionCoordinator::generate_xid() {
    return "sqlproxy_" + utils::generate_uuid();
}

std::string TransactionCoordinator::begin_transaction(const std::string& user) {
    if (!config_.enabled) return "";

    std::unique_lock lock(txn_mutex_);

    // Check max active limit
    if (transactions_.size() >= config_.max_active_transactions) {
        return "";
    }

    const auto xid = generate_xid();
    const auto now = std::chrono::steady_clock::now();

    DistributedTransaction txn;
    txn.xid = xid;
    txn.user = user;
    txn.state = TxnState::ACTIVE;
    txn.created_at = now;
    txn.last_activity = now;

    transactions_[xid] = std::move(txn);
    started_.fetch_add(1, std::memory_order_relaxed);

    return xid;
}

bool TransactionCoordinator::enlist_participant(
    const std::string& xid, const std::string& database) {
    if (!config_.enabled) return false;

    std::unique_lock lock(txn_mutex_);
    auto it = transactions_.find(xid);
    if (it == transactions_.end()) return false;

    auto& txn = it->second;
    if (txn.state != TxnState::ACTIVE) return false;

    // Check for duplicate
    for (const auto& p : txn.participants) {
        if (p.database == database) return true; // Already enlisted
    }

    TxnParticipant participant;
    participant.database = database;
    participant.local_state = TxnState::ACTIVE;
    participant.joined_at = std::chrono::steady_clock::now();

    txn.participants.emplace_back(std::move(participant));
    txn.last_activity = std::chrono::steady_clock::now();

    return true;
}

bool TransactionCoordinator::prepare(const std::string& xid) {
    if (!config_.enabled) return false;

    std::unique_lock lock(txn_mutex_);
    auto it = transactions_.find(xid);
    if (it == transactions_.end()) return false;

    auto& txn = it->second;
    if (!is_valid_transition(txn.state, TxnState::PREPARING)) return false;

    // Must have at least one participant
    if (txn.participants.empty()) return false;

    txn.state = TxnState::PREPARING;
    txn.last_activity = std::chrono::steady_clock::now();

    // Prepare all participants
    for (auto& p : txn.participants) {
        p.local_state = TxnState::PREPARED;
    }

    txn.state = TxnState::PREPARED;
    return true;
}

bool TransactionCoordinator::commit(const std::string& xid) {
    if (!config_.enabled) return false;

    std::unique_lock lock(txn_mutex_);
    auto it = transactions_.find(xid);
    if (it == transactions_.end()) return false;

    auto& txn = it->second;
    if (!is_valid_transition(txn.state, TxnState::COMMITTING)) return false;

    txn.state = TxnState::COMMITTING;
    txn.last_activity = std::chrono::steady_clock::now();

    // Commit all participants
    for (auto& p : txn.participants) {
        p.local_state = TxnState::COMMITTED;
    }

    txn.state = TxnState::COMMITTED;
    committed_.fetch_add(1, std::memory_order_relaxed);

    return true;
}

bool TransactionCoordinator::rollback(const std::string& xid) {
    if (!config_.enabled) return false;

    std::unique_lock lock(txn_mutex_);
    auto it = transactions_.find(xid);
    if (it == transactions_.end()) return false;

    auto& txn = it->second;
    if (!is_valid_transition(txn.state, TxnState::ABORTING)) return false;

    txn.state = TxnState::ABORTING;
    txn.last_activity = std::chrono::steady_clock::now();

    for (auto& p : txn.participants) {
        p.local_state = TxnState::ABORTED;
    }

    txn.state = TxnState::ABORTED;
    aborted_.fetch_add(1, std::memory_order_relaxed);

    return true;
}

// ============================================================================
// Query State
// ============================================================================

std::optional<DistributedTransaction> TransactionCoordinator::get_transaction(
    const std::string& xid) const {
    std::shared_lock lock(txn_mutex_);
    const auto it = transactions_.find(xid);
    if (it == transactions_.end()) return std::nullopt;
    return it->second;
}

std::vector<DistributedTransaction> TransactionCoordinator::active_transactions() const {
    std::shared_lock lock(txn_mutex_);
    std::vector<DistributedTransaction> result;
    for (const auto& [_, txn] : transactions_) {
        if (txn.state != TxnState::COMMITTED && txn.state != TxnState::ABORTED) {
            result.push_back(txn);
        }
    }
    return result;
}

// ============================================================================
// Background Cleanup
// ============================================================================

void TransactionCoordinator::start_cleanup() {
    if (running_.exchange(true)) return;
    cleanup_thread_ = std::thread([this] { cleanup_loop(); });
}

void TransactionCoordinator::stop_cleanup() {
    if (!running_.exchange(false)) return;
    cleanup_cv_.notify_all();
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
}

void TransactionCoordinator::cleanup_loop() {
    while (running_.load(std::memory_order_relaxed)) {
        std::unique_lock lock(cleanup_mutex_);
        cleanup_cv_.wait_for(lock,
            std::chrono::seconds(config_.cleanup_interval_seconds),
            [this] { return !running_.load(std::memory_order_relaxed); });

        if (!running_.load(std::memory_order_relaxed)) break;

        timeout_stale_transactions();
    }
}

void TransactionCoordinator::timeout_stale_transactions() {
    const auto now = std::chrono::steady_clock::now();
    const auto timeout = std::chrono::milliseconds(config_.timeout_ms);

    std::unique_lock lock(txn_mutex_);

    std::vector<std::string> to_remove;

    for (auto& [xid, txn] : transactions_) {
        // Skip terminal states
        if (txn.state == TxnState::COMMITTED || txn.state == TxnState::ABORTED) {
            // Remove completed transactions older than timeout
            if (now - txn.last_activity > timeout) {
                to_remove.push_back(xid);
            }
            continue;
        }

        // Timeout active transactions
        if (now - txn.last_activity > timeout) {
            txn.state = TxnState::ABORTED;
            for (auto& p : txn.participants) {
                p.local_state = TxnState::ABORTED;
            }
            timed_out_.fetch_add(1, std::memory_order_relaxed);
            aborted_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    for (const auto& xid : to_remove) {
        transactions_.erase(xid);
    }
}

// ============================================================================
// Stats
// ============================================================================

TransactionCoordinator::Stats TransactionCoordinator::get_stats() const {
    std::shared_lock lock(txn_mutex_);
    size_t active = 0;
    for (const auto& [_, txn] : transactions_) {
        if (txn.state != TxnState::COMMITTED && txn.state != TxnState::ABORTED) {
            ++active;
        }
    }

    return {
        started_.load(std::memory_order_relaxed),
        committed_.load(std::memory_order_relaxed),
        aborted_.load(std::memory_order_relaxed),
        timed_out_.load(std::memory_order_relaxed),
        active
    };
}

} // namespace sqlproxy
