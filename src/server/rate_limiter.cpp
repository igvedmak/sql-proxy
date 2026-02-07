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
    auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    // Retry limit prevents infinite spin under extreme contention
    static constexpr int kMaxRetries = 8;

    for (int attempt = 0; attempt < kMaxRetries; ++attempt) {
        uint32_t current_tokens = tokens_.load(std::memory_order_acquire);
        int64_t last_refill = last_refill_ns_.load(std::memory_order_acquire);

        // Refill tokens based on elapsed time (full 64-bit nanoseconds, no overflow)
        int64_t elapsed_ns = now_ns - last_refill;
        double elapsed_seconds = static_cast<double>(elapsed_ns) / 1e9;

        // Calculate new tokens
        uint32_t tokens_to_add = static_cast<uint32_t>(
            elapsed_seconds * tokens_per_second_);
        uint32_t new_tokens = std::min(current_tokens + tokens_to_add, burst_capacity_);

        // Check if enough tokens available
        if (new_tokens < tokens) {
            return false; // Rate limited
        }

        // Try to consume tokens (CAS on token count)
        uint32_t tokens_after_consume = new_tokens - tokens;

        if (tokens_.compare_exchange_weak(current_tokens, tokens_after_consume,
                                          std::memory_order_release,
                                          std::memory_order_acquire)) {
            // Update last refill timestamp (best-effort; concurrent updates are harmless
            // since the next CAS iteration will re-read and recalculate)
            last_refill_ns_.store(now_ns, std::memory_order_release);
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
    auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
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
}

RateLimitResult HierarchicalRateLimiter::check(
    const std::string& user,
    const std::string& database) {

    total_checks_.fetch_add(1, std::memory_order_relaxed);

    // Level 1: Global
    if (!global_bucket_->try_acquire()) {
        global_rejects_.fetch_add(1, std::memory_order_relaxed);
        return RateLimitResult{
            false,
            0,
            std::chrono::milliseconds(1000), // Retry after 1 second
            "global"
        };
    }

    // Level 2: Per-User
    auto user_bucket = get_user_bucket(user);
    if (!user_bucket->try_acquire()) {
        user_rejects_.fetch_add(1, std::memory_order_relaxed);
        return RateLimitResult{
            false,
            user_bucket->available_tokens(),
            std::chrono::milliseconds(100),
            "user"
        };
    }

    // Level 3: Per-Database
    auto db_bucket = get_database_bucket(database);
    if (!db_bucket->try_acquire()) {
        database_rejects_.fetch_add(1, std::memory_order_relaxed);
        return RateLimitResult{
            false,
            db_bucket->available_tokens(),
            std::chrono::milliseconds(100),
            "database"
        };
    }

    // Level 4: Per-User-Per-Database
    auto user_db_bucket = get_user_database_bucket(user, database);
    if (!user_db_bucket->try_acquire()) {
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
    return Stats{
        total_checks_.load(std::memory_order_relaxed),
        global_rejects_.load(std::memory_order_relaxed),
        user_rejects_.load(std::memory_order_relaxed),
        database_rejects_.load(std::memory_order_relaxed),
        user_database_rejects_.load(std::memory_order_relaxed)
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

} // namespace sqlproxy
