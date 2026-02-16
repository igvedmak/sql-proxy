#pragma once

#include "server/irate_limiter.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace sqlproxy {

/**
 * @brief Abstract backend interface for distributed rate limiting.
 *
 * Implementations can be in-memory (single-node) or Redis-backed (multi-node).
 */
class IDistributedBackend {
public:
    virtual ~IDistributedBackend() = default;

    virtual void report_usage(const std::string& key, uint64_t tokens_consumed) = 0;

    [[nodiscard]] virtual uint64_t get_global_usage(const std::string& key) = 0;

    [[nodiscard]] virtual uint32_t node_count() const = 0;

    virtual void reset() = 0;
};

/**
 * @brief In-memory distributed backend for single-node and testing.
 */
class InMemoryDistributedBackend : public IDistributedBackend {
public:
    explicit InMemoryDistributedBackend(uint32_t simulated_nodes = 1);

    void report_usage(const std::string& key, uint64_t tokens_consumed) override;

    [[nodiscard]] uint64_t get_global_usage(const std::string& key) override;

    [[nodiscard]] uint32_t node_count() const override { return node_count_; }

    void reset() override;

private:
    uint32_t node_count_;
    std::unordered_map<std::string, uint64_t> usage_;
    mutable std::shared_mutex mutex_;
};

/**
 * @brief Distributed rate limiter — decorator around IRateLimiter.
 *
 * Two-tier approach:
 * - Local tier (fast path): Delegates to wrapped IRateLimiter with 1/N budget
 * - Global tier (slow path): Periodic sync with backend to adjust quotas
 *
 * Background thread reconciles local usage with the global view every sync_interval_ms.
 */
class DistributedRateLimiter : public IRateLimiter {
public:
    struct Config {
        bool enabled = false;
        std::string node_id = "node-1";
        uint32_t cluster_size = 1;
        uint32_t sync_interval_ms = 5000;
        std::string backend_type = "memory";
    };

    DistributedRateLimiter(std::shared_ptr<IRateLimiter> local,
                           std::shared_ptr<IDistributedBackend> backend,
                           Config config);

    ~DistributedRateLimiter();

    [[nodiscard]] bool is_enabled() const { return config_.enabled; }

    // IRateLimiter interface — delegates to local limiter
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

    void start_sync();
    void stop_sync();

    struct Stats {
        uint64_t sync_cycles = 0;
        uint64_t backend_errors = 0;
        uint64_t total_checks = 0;
        uint64_t global_overrides = 0;
    };

    [[nodiscard]] Stats get_stats() const;

    [[nodiscard]] std::shared_ptr<IRateLimiter> get_inner() const { return local_; }

private:
    void sync_loop();

    std::shared_ptr<IRateLimiter> local_;
    std::shared_ptr<IDistributedBackend> backend_;
    Config config_;

    // Background sync
    std::thread sync_thread_;
    std::atomic<bool> running_{false};
    std::mutex sync_mutex_;
    std::condition_variable sync_cv_;

    // Usage tracking
    std::unordered_map<std::string, std::atomic<uint64_t>> local_usage_;
    mutable std::shared_mutex usage_mutex_;

    // Stats
    std::atomic<uint64_t> sync_cycles_{0};
    std::atomic<uint64_t> backend_errors_{0};
    std::atomic<uint64_t> total_checks_{0};
    std::atomic<uint64_t> global_overrides_{0};
};

} // namespace sqlproxy
