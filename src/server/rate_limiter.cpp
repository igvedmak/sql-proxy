#include "server/rate_limiter.hpp"
#include <algorithm>
#include <mutex>
#include <shared_mutex>
#include <thread>

#ifdef __x86_64__
#include <immintrin.h>
#endif

namespace sqlproxy {

// ============================================================================
// TokenBucket Implementation
// ============================================================================

TokenBucket::TokenBucket(uint32_t tokens_per_second, uint32_t burst_capacity)
    : tokens_per_second_(tokens_per_second),
      burst_capacity_(burst_capacity),
      tokens_(0),
      last_refill_ns_(0) {

    // Initialize with full capacity
    reset();
}

bool TokenBucket::try_acquire(uint32_t tokens) {
    const auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return try_acquire_at(now_ns, tokens);
}

bool TokenBucket::try_acquire_at(int64_t now_ns, uint32_t tokens) {
    // Phase 1: Refill — at most one thread wins per time period via CAS on last_refill_ns_
    // This prevents the phantom-refill bug where multiple threads each add the same
    // refill tokens because they all read a stale last_refill timestamp.
    {
        int64_t last_refill = last_refill_ns_.load(std::memory_order_acquire);
        const int64_t elapsed_ns = now_ns - last_refill;
        if (elapsed_ns > 0) {
            // tokens_to_add = elapsed_ns * tokens_per_second / 1e9
            // Safe for int64_t: even 1 hour * 50K tps = 1.8e17, well within 9.2e18 limit
            const int64_t raw_tokens = elapsed_ns * static_cast<int64_t>(tokens_per_second_) / 1'000'000'000LL;
            if (raw_tokens > 0) {
                // Claim this refill period — only one thread succeeds
                if (last_refill_ns_.compare_exchange_strong(last_refill, now_ns,
                                                             std::memory_order_acq_rel,
                                                             std::memory_order_acquire)) {
                    const uint32_t add = static_cast<uint32_t>(
                        std::min(raw_tokens, static_cast<int64_t>(burst_capacity_)));

                    // CAS loop to add refill tokens with burst cap
                    uint32_t old_val = tokens_.load(std::memory_order_relaxed);
                    uint32_t new_val;
                    do {
                        new_val = std::min(old_val + add, burst_capacity_);
                    } while (!tokens_.compare_exchange_weak(old_val, new_val,
                                                             std::memory_order_release,
                                                             std::memory_order_relaxed));
                }
            }
        }
    }

    // Phase 2: Consume — CAS loop to atomically deduct tokens
    static constexpr int kMaxRetries = 8;
    for (int attempt = 0; attempt < kMaxRetries; ++attempt) {
        uint32_t current = tokens_.load(std::memory_order_acquire);
        if (current < tokens) {
            return false; // Rate limited
        }

        if (tokens_.compare_exchange_weak(current, current - tokens,
                                          std::memory_order_release,
                                          std::memory_order_acquire)) {
            return true; // Successfully acquired tokens
        }

        // CAS failed: pause hint reduces CPU pipeline stalls during spin-wait
#ifdef __x86_64__
        _mm_pause();
#elif defined(__aarch64__)
        asm volatile("yield" ::: "memory");
#endif
    }

    // All retries exhausted under extreme contention - treat as rate limited
    return false;
}

uint32_t TokenBucket::available_tokens() const {
    return tokens_.load(std::memory_order_acquire);
}

void TokenBucket::reset() {
    const auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    tokens_.store(burst_capacity_, std::memory_order_release);
    last_refill_ns_.store(now_ns, std::memory_order_release);
}

// ============================================================================
// HierarchicalRateLimiter Implementation
// ============================================================================

HierarchicalRateLimiter::HierarchicalRateLimiter(const Config& config)
    : config_(config),
      total_checks_(0),
      global_rejects_(0),
      user_rejects_(0),
      database_rejects_(0),
      user_database_rejects_(0) {

    // Create global bucket
    global_bucket_ = std::make_unique<TokenBucket>(
        config_.global_tokens_per_second,
        config_.global_burst_capacity
    );

    // Start cleanup thread if idle timeout is configured
    if (config_.bucket_idle_timeout_seconds > 0) {
        cleanup_running_.store(true, std::memory_order_release);
        cleanup_thread_ = std::thread([this]() { cleanup_loop(); });
    }
}

HierarchicalRateLimiter::~HierarchicalRateLimiter() {
    cleanup_running_.store(false, std::memory_order_release);
    cleanup_cv_.notify_all();
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
}

RateLimitResult HierarchicalRateLimiter::check(
    const std::string& user,
    const std::string& database) {

    total_checks_.fetch_add(1, std::memory_order_relaxed);

    // Read timestamp ONCE for all 4 bucket checks
    // Saves ~60ns (3 eliminated steady_clock::now() calls at ~20ns each)
    const auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    // Level 1: Global
    if (!global_bucket_->try_acquire_at(now_ns)) {
        global_rejects_.fetch_add(1, std::memory_order_relaxed);
        return RateLimitResult{
            false,
            0,
            std::chrono::milliseconds(1000), // Retry after 1 second
            "global"
        };
    }

    // Level 2: Per-User
    const auto user_bucket = get_user_bucket(user);
    if (!user_bucket->try_acquire_at(now_ns)) {
        user_rejects_.fetch_add(1, std::memory_order_relaxed);
        return RateLimitResult{
            false,
            user_bucket->available_tokens(),
            std::chrono::milliseconds(100),
            "user"
        };
    }

    // Level 3: Per-Database
    const auto db_bucket = get_database_bucket(database);
    if (!db_bucket->try_acquire_at(now_ns)) {
        database_rejects_.fetch_add(1, std::memory_order_relaxed);
        return RateLimitResult{
            false,
            db_bucket->available_tokens(),
            std::chrono::milliseconds(100),
            "database"
        };
    }

    // Level 4: Per-User-Per-Database
    const auto user_db_bucket = get_user_database_bucket(user, database);
    if (!user_db_bucket->try_acquire_at(now_ns)) {
        user_database_rejects_.fetch_add(1, std::memory_order_relaxed);
        return RateLimitResult{
            false,
            user_db_bucket->available_tokens(),
            std::chrono::milliseconds(50),
            "user_database"
        };
    }

    // All levels passed
    return RateLimitResult{
        true,
        user_db_bucket->available_tokens(),
        std::chrono::milliseconds(0),
        ""
    };
}

void HierarchicalRateLimiter::set_user_limit(
    const std::string& user,
    uint32_t tokens_per_second,
    uint32_t burst_capacity) {

    std::unique_lock<std::shared_mutex> lock(user_buckets_mutex_);
    user_buckets_[user] = std::make_shared<TokenBucket>(
        tokens_per_second, burst_capacity);
}

void HierarchicalRateLimiter::set_database_limit(
    const std::string& database,
    uint32_t tokens_per_second,
    uint32_t burst_capacity) {

    std::unique_lock<std::shared_mutex> lock(db_buckets_mutex_);
    db_buckets_[database] = std::make_shared<TokenBucket>(
        tokens_per_second, burst_capacity);
}

void HierarchicalRateLimiter::set_user_database_limit(
    const std::string& user,
    const std::string& database,
    uint32_t tokens_per_second,
    uint32_t burst_capacity) {

    // Optimized string concatenation
    std::string key;
    key.reserve(user.size() + 1 + database.size());
    key = user;
    key += ':';
    key += database;

    std::unique_lock<std::shared_mutex> lock(user_db_buckets_mutex_);
    user_db_buckets_[key] = std::make_shared<TokenBucket>(
        tokens_per_second, burst_capacity);
}

void HierarchicalRateLimiter::adjust_global_rate(uint32_t new_tps, uint32_t new_burst) {
    global_bucket_ = std::make_unique<TokenBucket>(new_tps, new_burst);
}

void HierarchicalRateLimiter::reset_all() {
    global_bucket_->reset();

    {
        std::unique_lock<std::shared_mutex> lock(user_buckets_mutex_);
        for (auto& [user, bucket] : user_buckets_) {
            bucket->reset();
        }
    }

    {
        std::unique_lock<std::shared_mutex> lock(db_buckets_mutex_);
        for (auto& [db, bucket] : db_buckets_) {
            bucket->reset();
        }
    }

    {
        std::unique_lock<std::shared_mutex> lock(user_db_buckets_mutex_);
        for (auto& [key, bucket] : user_db_buckets_) {
            bucket->reset();
        }
    }
}

HierarchicalRateLimiter::Stats HierarchicalRateLimiter::get_stats() const {
    size_t ub = 0, db = 0, udb = 0;
    {
        std::shared_lock<std::shared_mutex> lock(user_buckets_mutex_);
        ub = user_buckets_.size();
    }
    {
        std::shared_lock<std::shared_mutex> lock(db_buckets_mutex_);
        db = db_buckets_.size();
    }
    {
        std::shared_lock<std::shared_mutex> lock(user_db_buckets_mutex_);
        udb = user_db_buckets_.size();
    }
    return Stats{
        .total_checks = total_checks_.load(std::memory_order_relaxed),
        .global_rejects = global_rejects_.load(std::memory_order_relaxed),
        .user_rejects = user_rejects_.load(std::memory_order_relaxed),
        .database_rejects = database_rejects_.load(std::memory_order_relaxed),
        .user_database_rejects = user_database_rejects_.load(std::memory_order_relaxed),
        .buckets_evicted = buckets_evicted_.load(std::memory_order_relaxed),
        .user_bucket_count = ub,
        .db_bucket_count = db,
        .user_db_bucket_count = udb,
    };
}

std::shared_ptr<TokenBucket> HierarchicalRateLimiter::get_user_bucket(
    const std::string& user) {

    // Fast path: shared lock for read (99.9% of requests)
    {
        std::shared_lock<std::shared_mutex> lock(user_buckets_mutex_);
        const auto it = user_buckets_.find(user);
        if (it != user_buckets_.end()) {
            return it->second;
        }
    }

    // Slow path: unique lock for write
    std::unique_lock<std::shared_mutex> lock(user_buckets_mutex_);

    // Double-check: another thread may have created it
    auto [it, inserted] = user_buckets_.try_emplace(
        user,
        nullptr
    );

    if (inserted) {
        // We inserted, create the bucket
        it->second = std::make_shared<TokenBucket>(
            config_.default_user_tokens_per_second,
            config_.default_user_burst_capacity
        );
    }

    return it->second;
}

std::shared_ptr<TokenBucket> HierarchicalRateLimiter::get_database_bucket(
    const std::string& database) {

    // Fast path: shared lock for read
    {
        std::shared_lock<std::shared_mutex> lock(db_buckets_mutex_);
        const auto it = db_buckets_.find(database);
        if (it != db_buckets_.end()) {
            return it->second;
        }
    }

    // Slow path: unique lock for write
    std::unique_lock<std::shared_mutex> lock(db_buckets_mutex_);

    // Double-check pattern
    auto [it, inserted] = db_buckets_.try_emplace(
        database,
        nullptr
    );

    if (inserted) {
        it->second = std::make_shared<TokenBucket>(
            config_.default_db_tokens_per_second,
            config_.default_db_burst_capacity
        );
    }

    return it->second;
}

std::shared_ptr<TokenBucket> HierarchicalRateLimiter::get_user_database_bucket(
    const std::string& user,
    const std::string& database) {

    // Pre-allocate key string to avoid multiple allocations
    std::string key;
    key.reserve(user.size() + 1 + database.size());
    key = user;
    key += ':';
    key += database;

    // Fast path: shared lock for read
    {
        std::shared_lock<std::shared_mutex> lock(user_db_buckets_mutex_);
        const auto it = user_db_buckets_.find(key);
        if (it != user_db_buckets_.end()) {
            return it->second;
        }
    }

    // Slow path: unique lock for write
    std::unique_lock<std::shared_mutex> lock(user_db_buckets_mutex_);

    // Double-check pattern
    auto [it, inserted] = user_db_buckets_.try_emplace(
        std::move(key),
        nullptr
    );

    if (inserted) {
        it->second = std::make_shared<TokenBucket>(
            config_.default_user_db_tokens_per_second,
            config_.default_user_db_burst_capacity
        );
    }

    return it->second;
}

void HierarchicalRateLimiter::cleanup_loop() {
    const auto idle_timeout_ns = static_cast<int64_t>(config_.bucket_idle_timeout_seconds) * 1'000'000'000LL;

    while (cleanup_running_.load(std::memory_order_acquire)) {
        // Wait for cleanup interval or shutdown signal
        {
            std::unique_lock<std::mutex> lock(cleanup_mutex_);
            cleanup_cv_.wait_for(lock,
                std::chrono::seconds(config_.cleanup_interval_seconds),
                [this]() { return !cleanup_running_.load(std::memory_order_acquire); });
        }

        if (!cleanup_running_.load(std::memory_order_acquire)) break;

        const auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();

        uint64_t evicted = 0;

        // Sweep user buckets
        {
            std::unique_lock<std::shared_mutex> lock(user_buckets_mutex_);
            for (auto it = user_buckets_.begin(); it != user_buckets_.end(); ) {
                if (now_ns - it->second->last_access_ns() > idle_timeout_ns) {
                    it = user_buckets_.erase(it);
                    ++evicted;
                } else {
                    ++it;
                }
            }
        }

        // Sweep database buckets
        {
            std::unique_lock<std::shared_mutex> lock(db_buckets_mutex_);
            for (auto it = db_buckets_.begin(); it != db_buckets_.end(); ) {
                if (now_ns - it->second->last_access_ns() > idle_timeout_ns) {
                    it = db_buckets_.erase(it);
                    ++evicted;
                } else {
                    ++it;
                }
            }
        }

        // Sweep user-database buckets
        {
            std::unique_lock<std::shared_mutex> lock(user_db_buckets_mutex_);
            for (auto it = user_db_buckets_.begin(); it != user_db_buckets_.end(); ) {
                if (now_ns - it->second->last_access_ns() > idle_timeout_ns) {
                    it = user_db_buckets_.erase(it);
                    ++evicted;
                } else {
                    ++it;
                }
            }
        }

        if (evicted > 0) {
            buckets_evicted_.fetch_add(evicted, std::memory_order_relaxed);
        }
    }
}

} // namespace sqlproxy
