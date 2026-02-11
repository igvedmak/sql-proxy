#pragma once

#include "executor/circuit_breaker.hpp"
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace sqlproxy {

/**
 * @brief Registry of per-tenant (or per-key) circuit breakers.
 *
 * Lazily creates circuit breakers on first access using double-checked locking
 * with a shared_mutex for read-heavy workloads (99.9% lookups, 0.1% creates).
 *
 * Key format: "tenant_id:database" (or just "database" for non-tenant requests).
 *
 * Performance: ~20ns for existing breaker lookup (shared_lock path).
 */
class CircuitBreakerRegistry {
public:
    explicit CircuitBreakerRegistry(const CircuitBreaker::Config& default_config);

    /**
     * @brief Get or create circuit breaker for a given key.
     *
     * Uses double-checked locking: shared_lock for fast path (existing),
     * unique_lock + try_emplace for slow path (creation).
     *
     * @param key Breaker key (e.g., "acme:prod_db")
     * @return Shared pointer to the breaker (never null)
     */
    [[nodiscard]] std::shared_ptr<CircuitBreaker> get_breaker(const std::string& key);

    /**
     * @brief Set per-tenant config override.
     * Affects subsequently created breakers for this tenant.
     */
    void set_tenant_config(const std::string& tenant_id, const CircuitBreaker::Config& config);

    /**
     * @brief Get stats for all breakers in the registry.
     * @return Vector of (key, stats) pairs.
     */
    [[nodiscard]] std::vector<std::pair<std::string, CircuitBreakerStats>> get_all_stats() const;

    /**
     * @brief Get number of breakers in the registry.
     */
    [[nodiscard]] size_t size() const;

private:
    CircuitBreaker::Config default_config_;

    // Breaker storage (double-checked locking pattern)
    std::unordered_map<std::string, std::shared_ptr<CircuitBreaker>> breakers_;
    mutable std::shared_mutex breakers_mutex_;

    // Per-tenant config overrides
    std::unordered_map<std::string, CircuitBreaker::Config> tenant_configs_;
    mutable std::shared_mutex config_mutex_;
};

} // namespace sqlproxy
