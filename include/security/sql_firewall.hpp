#pragma once

#include <atomic>
#include <cstdint>
#include <shared_mutex>
#include <string>
#include <unordered_set>
#include <vector>

namespace sqlproxy {

enum class FirewallMode : uint8_t { DISABLED, LEARNING, ENFORCING };

inline const char* firewall_mode_to_string(FirewallMode mode) {
    switch (mode) {
        case FirewallMode::DISABLED:  return "disabled";
        case FirewallMode::LEARNING:  return "learning";
        case FirewallMode::ENFORCING: return "enforcing";
        default:                      return "disabled";
    }
}

class SqlFirewall {
public:
    struct Config {
        bool enabled = false;
        FirewallMode initial_mode = FirewallMode::DISABLED;
    };

    struct CheckResult {
        bool allowed;
        bool is_new_fingerprint;
    };

    SqlFirewall();
    explicit SqlFirewall(Config config);

    [[nodiscard]] CheckResult check(uint64_t fingerprint_hash) const;
    void record(uint64_t fingerprint_hash);
    void set_mode(FirewallMode mode);
    [[nodiscard]] FirewallMode mode() const;
    [[nodiscard]] bool is_enabled() const { return config_.enabled; }
    [[nodiscard]] size_t allowlist_size() const;
    [[nodiscard]] std::vector<uint64_t> get_allowlist() const;

private:
    Config config_;
    std::atomic<FirewallMode> mode_;
    mutable std::shared_mutex mutex_;
    std::unordered_set<uint64_t> allowlist_;
};

} // namespace sqlproxy
