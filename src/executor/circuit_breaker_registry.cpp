#include "executor/circuit_breaker_registry.hpp"

namespace sqlproxy {

CircuitBreakerRegistry::CircuitBreakerRegistry(const CircuitBreaker::Config& default_config)
    : default_config_(default_config) {}

std::shared_ptr<CircuitBreaker> CircuitBreakerRegistry::get_breaker(const std::string& key) {
    // Fast path: shared lock (read-only)
    {
        std::shared_lock lock(breakers_mutex_);
        const auto it = breakers_.find(key);
        if (it != breakers_.end()) {
            return it->second;
        }
    }

    // Pre-compute config BEFORE taking breakers_mutex_ unique lock
    // (eliminates nested config_mutex_ inside breakers_mutex_)
    CircuitBreaker::Config cfg = default_config_;
    const auto colon = key.find(':');
    if (colon != std::string::npos) {
        const std::string tenant_id = key.substr(0, colon);
        std::shared_lock cfg_lock(config_mutex_);
        const auto cfg_it = tenant_configs_.find(tenant_id);
        if (cfg_it != tenant_configs_.end()) {
            cfg = cfg_it->second;
        }
    }

    // Slow path: unique lock + try_emplace
    std::unique_lock lock(breakers_mutex_);
    auto [it, inserted] = breakers_.try_emplace(key, nullptr);
    if (inserted) {
        it->second = std::make_shared<CircuitBreaker>(key, cfg);
    }
    return it->second;
}

void CircuitBreakerRegistry::set_tenant_config(
    const std::string& tenant_id, const CircuitBreaker::Config& config) {
    std::unique_lock lock(config_mutex_);
    tenant_configs_[tenant_id] = config;
}

std::vector<std::pair<std::string, CircuitBreakerStats>>
CircuitBreakerRegistry::get_all_stats() const {
    std::shared_lock lock(breakers_mutex_);
    std::vector<std::pair<std::string, CircuitBreakerStats>> result;
    result.reserve(breakers_.size());
    for (const auto& [key, breaker] : breakers_) {
        result.emplace_back(key, breaker->get_stats());
    }
    return result;
}

size_t CircuitBreakerRegistry::size() const {
    std::shared_lock lock(breakers_mutex_);
    return breakers_.size();
}

} // namespace sqlproxy
