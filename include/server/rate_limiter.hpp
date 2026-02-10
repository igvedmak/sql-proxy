#pragma once

#include "core/types.hpp"
#include "server/irate_limiter.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <shared_mutex>  // C++17 reader-writer locks
#include <string>

namespace sqlproxy {

/**
 * @brief Lock-free token bucket rate limiter
 *
 * Token bucket algorithm with atomic operations:
 * - Tokens refill at constant rate (tokens_per_second)
 * - Burst capacity allows temporary spikes
 * - Lock-free: uses atomic CAS for token consumption
 *
 * Performance: ~20ns per acquire attempt
 */
class TokenBucket {
public:
    /**
     * @brief Construct token bucket
     * @param tokens_per_second Refill rate
     * @param burst_capacity Maximum burst size
     */
    TokenBucket(uint32_t tokens_per_second, uint32_t burst_capacity);

    /**
     * @brief Try to acquire N tokens
     * @param tokens Number of tokens to acquire (default: 1)
     * @return true if tokens acquired, false if rate limited
     */
    bool try_acquire(uint32_t tokens = 1);

    /**
     * @brief Try to acquire tokens with pre-computed timestamp
     * Avoids calling steady_clock::now() per bucket (saves ~20ns per call)
     */
    bool try_acquire_at(int64_t now_ns, uint32_t tokens = 1);

    /**
     * @brief Get current token count (approximate)
     */
    uint32_t available_tokens() const;

    /**
     * @brief Reset bucket to full capacity
     */
    void reset();

    /**
     * @brief Get last access time (nanoseconds since steady_clock epoch)
     */
    [[nodiscard]] int64_t last_access_ns() const {
        return last_refill_ns_.load(std::memory_order_relaxed);
    }

private:
    uint32_t tokens_per_second_;
    uint32_t burst_capacity_;

    // Separate atomics to avoid 32-bit timestamp overflow (~49 day limit)
    std::atomic<uint32_t> tokens_;
    std::atomic<int64_t> last_refill_ns_;  // Full precision nanoseconds (steady_clock)
};

/**
 * @brief Hierarchical rate limiter (4 levels)
 *
 * ALL levels must pass for request to be allowed:
 * 1. Global         - Protects proxy CPU (50K req/sec)
 * 2. Per-User       - Prevents one user starving others
 * 3. Per-Database   - Protects each DB independently
 * 4. Per-User-Per-DB - Most specific control
 *
 * Performance: ~80ns for all 4 checks (lock-free atomic operations)
 *
 * Thread-safety: Fully thread-safe via atomic operations
 */
class HierarchicalRateLimiter : public IRateLimiter {
public:
    /**
     * @brief Configuration for rate limits
     */
    struct Config {
        // Level 1: Global
        uint32_t global_tokens_per_second = 50000;
        uint32_t global_burst_capacity = 10000;

        // Level 2: Per-User (default)
        uint32_t default_user_tokens_per_second = 1000;
        uint32_t default_user_burst_capacity = 200;

        // Level 3: Per-Database (default)
        uint32_t default_db_tokens_per_second = 30000;
        uint32_t default_db_burst_capacity = 5000;

        // Level 4: Per-User-Per-Database (default)
        uint32_t default_user_db_tokens_per_second = 100;
        uint32_t default_user_db_burst_capacity = 20;

        // Bucket cleanup
        uint32_t bucket_idle_timeout_seconds = 3600;   // 0 = disabled
        uint32_t cleanup_interval_seconds = 60;
    };

    /**
     * @brief Construct rate limiter with config
     */
    explicit HierarchicalRateLimiter(const Config& config);

    /**
     * @brief Check if request is allowed (all 4 levels)
     * @param user User identifier
     * @param database Database name
     * @return Rate limit result
     */
    [[nodiscard]] RateLimitResult check(
        const std::string& user, const std::string& database) override;

    void set_user_limit(const std::string& user,
                       uint32_t tokens_per_second,
                       uint32_t burst_capacity) override;

    void set_database_limit(const std::string& database,
                           uint32_t tokens_per_second,
                           uint32_t burst_capacity) override;

    void set_user_database_limit(const std::string& user,
                                const std::string& database,
                                uint32_t tokens_per_second,
                                uint32_t burst_capacity) override;

    void reset_all() override;

    /**
     * @brief Adjust global rate limit (used by adaptive rate controller)
     * @param new_tps New tokens per second
     * @param new_burst New burst capacity
     */
    void adjust_global_rate(uint32_t new_tps, uint32_t new_burst);

    /**
     * @brief Get statistics
     */
    struct Stats {
        uint64_t total_checks;
        uint64_t global_rejects;
        uint64_t user_rejects;
        uint64_t database_rejects;
        uint64_t user_database_rejects;
        uint64_t buckets_evicted;
        size_t user_bucket_count;
        size_t db_bucket_count;
        size_t user_db_bucket_count;
    };

    Stats get_stats() const;

    ~HierarchicalRateLimiter();

private:
    /**
     * @brief Get or create user bucket
     */
    std::shared_ptr<TokenBucket> get_user_bucket(const std::string& user);

    /**
     * @brief Get or create database bucket
     */
    std::shared_ptr<TokenBucket> get_database_bucket(const std::string& database);

    /**
     * @brief Get or create user-database bucket
     */
    std::shared_ptr<TokenBucket> get_user_database_bucket(
        const std::string& user, const std::string& database);

    Config config_;

    // Level 1: Global bucket
    std::unique_ptr<TokenBucket> global_bucket_;

    // Level 2: Per-User buckets
    std::unordered_map<std::string, std::shared_ptr<TokenBucket>> user_buckets_;
    mutable std::shared_mutex user_buckets_mutex_;

    // Level 3: Per-Database buckets
    std::unordered_map<std::string, std::shared_ptr<TokenBucket>> db_buckets_;
    mutable std::shared_mutex db_buckets_mutex_;

    // Level 4: Per-User-Per-Database buckets
    std::unordered_map<std::string, std::shared_ptr<TokenBucket>> user_db_buckets_;
    mutable std::shared_mutex user_db_buckets_mutex_;

    // Statistics (atomic)
    std::atomic<uint64_t> total_checks_;
    std::atomic<uint64_t> global_rejects_;
    std::atomic<uint64_t> user_rejects_;
    std::atomic<uint64_t> database_rejects_;
    std::atomic<uint64_t> user_database_rejects_;

    // Bucket cleanup
    void cleanup_loop();
    std::thread cleanup_thread_;
    std::atomic<bool> cleanup_running_{false};
    std::mutex cleanup_mutex_;
    std::condition_variable cleanup_cv_;
    std::atomic<uint64_t> buckets_evicted_{0};
};

} // namespace sqlproxy
