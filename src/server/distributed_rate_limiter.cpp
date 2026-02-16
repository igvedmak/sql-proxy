#include "server/distributed_rate_limiter.hpp"
#include "core/utils.hpp"
#include <format>

namespace sqlproxy {

// ============================================================================
// InMemoryDistributedBackend
// ============================================================================

InMemoryDistributedBackend::InMemoryDistributedBackend(uint32_t simulated_nodes)
    : node_count_(simulated_nodes < 1 ? 1 : simulated_nodes) {}

void InMemoryDistributedBackend::report_usage(const std::string& key,
                                               uint64_t tokens_consumed) {
    std::unique_lock lock(mutex_);
    usage_[key] += tokens_consumed;
}

uint64_t InMemoryDistributedBackend::get_global_usage(const std::string& key) {
    std::shared_lock lock(mutex_);
    const auto it = usage_.find(key);
    return (it != usage_.end()) ? it->second : 0;
}

void InMemoryDistributedBackend::reset() {
    std::unique_lock lock(mutex_);
    usage_.clear();
}

// ============================================================================
// DistributedRateLimiter
// ============================================================================

DistributedRateLimiter::DistributedRateLimiter(
    std::shared_ptr<IRateLimiter> local,
    std::shared_ptr<IDistributedBackend> backend,
    Config config)
    : local_(std::move(local))
    , backend_(std::move(backend))
    , config_(std::move(config)) {}

DistributedRateLimiter::~DistributedRateLimiter() {
    stop_sync();
}

RateLimitResult DistributedRateLimiter::check(
    const std::string& user, const std::string& database) {
    total_checks_.fetch_add(1, std::memory_order_relaxed);

    // Fast path: delegate to local limiter (1/N of global budget)
    auto result = local_->check(user, database);

    if (result.allowed) {
        // Track usage for background sync
        const std::string key = user + ":" + database;
        std::shared_lock lock(usage_mutex_);
        auto it = local_usage_.find(key);
        if (it != local_usage_.end()) {
            it->second.fetch_add(1, std::memory_order_relaxed);
        } else {
            lock.unlock();
            std::unique_lock wlock(usage_mutex_);
            local_usage_[key].store(1, std::memory_order_relaxed);
        }
        return result;
    }

    // Slow path: check global view — other nodes may have spare budget
    if (backend_) {
        const std::string key = user + ":" + database;
        try {
            const uint64_t global = backend_->get_global_usage(key);
            const uint32_t nodes = backend_->node_count();
            // If total global usage is below what we'd expect for N nodes,
            // override the local rejection
            if (nodes > 1 && global < (static_cast<uint64_t>(result.retry_after.count()) * nodes / 2)) {
                global_overrides_.fetch_add(1, std::memory_order_relaxed);
                result.allowed = true;
                result.level = "global_override";
                result.retry_after = std::chrono::milliseconds(0);
            }
        } catch (const std::exception& e) {
            backend_errors_.fetch_add(1, std::memory_order_relaxed);
            utils::log::error(std::format("Distributed rate limiter check failed: {}", e.what()));
        } catch (...) {
            backend_errors_.fetch_add(1, std::memory_order_relaxed);
            utils::log::error("Distributed rate limiter check failed: unknown error");
        }
    }

    return result;
}

void DistributedRateLimiter::set_user_limit(
    const std::string& user,
    uint32_t tokens_per_second,
    uint32_t burst_capacity) {
    // Divide budget by cluster size
    const uint32_t per_node_tps = tokens_per_second / config_.cluster_size;
    const uint32_t per_node_burst = burst_capacity / config_.cluster_size;
    local_->set_user_limit(user,
                           per_node_tps > 0 ? per_node_tps : 1,
                           per_node_burst > 0 ? per_node_burst : 1);
}

void DistributedRateLimiter::set_database_limit(
    const std::string& database,
    uint32_t tokens_per_second,
    uint32_t burst_capacity) {
    const uint32_t per_node_tps = tokens_per_second / config_.cluster_size;
    const uint32_t per_node_burst = burst_capacity / config_.cluster_size;
    local_->set_database_limit(database,
                               per_node_tps > 0 ? per_node_tps : 1,
                               per_node_burst > 0 ? per_node_burst : 1);
}

void DistributedRateLimiter::set_user_database_limit(
    const std::string& user,
    const std::string& database,
    uint32_t tokens_per_second,
    uint32_t burst_capacity) {
    const uint32_t per_node_tps = tokens_per_second / config_.cluster_size;
    const uint32_t per_node_burst = burst_capacity / config_.cluster_size;
    local_->set_user_database_limit(user, database,
                                    per_node_tps > 0 ? per_node_tps : 1,
                                    per_node_burst > 0 ? per_node_burst : 1);
}

void DistributedRateLimiter::reset_all() {
    local_->reset_all();
    if (backend_) {
        backend_->reset();
    }
    std::unique_lock lock(usage_mutex_);
    local_usage_.clear();
}

void DistributedRateLimiter::start_sync() {
    if (running_.exchange(true)) return;
    sync_thread_ = std::thread([this] { sync_loop(); });
}

void DistributedRateLimiter::stop_sync() {
    if (!running_.exchange(false)) return;
    sync_cv_.notify_all();
    if (sync_thread_.joinable()) {
        sync_thread_.join();
    }
}

DistributedRateLimiter::Stats DistributedRateLimiter::get_stats() const {
    return {
        sync_cycles_.load(std::memory_order_relaxed),
        backend_errors_.load(std::memory_order_relaxed),
        total_checks_.load(std::memory_order_relaxed),
        global_overrides_.load(std::memory_order_relaxed)
    };
}

void DistributedRateLimiter::sync_loop() {
    while (running_.load(std::memory_order_relaxed)) {
        std::unique_lock lock(sync_mutex_);
        sync_cv_.wait_for(lock,
            std::chrono::milliseconds(config_.sync_interval_ms),
            [this] { return !running_.load(std::memory_order_relaxed); });

        if (!running_.load(std::memory_order_relaxed)) break;

        // Report local usage to backend
        try {
            std::shared_lock ulock(usage_mutex_);
            for (const auto& [key, count] : local_usage_) {
                const uint64_t val = count.load(std::memory_order_relaxed);
                if (val > 0) {
                    backend_->report_usage(key, val);
                }
            }
            sync_cycles_.fetch_add(1, std::memory_order_relaxed);
        } catch (const std::exception& e) {
            backend_errors_.fetch_add(1, std::memory_order_relaxed);
            utils::log::error(std::format("Distributed rate limiter sync failed: {}", e.what()));
        } catch (...) {
            backend_errors_.fetch_add(1, std::memory_order_relaxed);
            utils::log::error("Distributed rate limiter sync failed: unknown error");
        }
    }
}

} // namespace sqlproxy
