#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <shared_mutex>

namespace sqlproxy {

class DataResidencyEnforcer {
public:
    struct Config {
        bool enabled = false;
    };

    struct CheckResult {
        bool allowed;
        std::string database_region;
        std::string reason;
    };

    DataResidencyEnforcer();
    explicit DataResidencyEnforcer(Config config);

    [[nodiscard]] bool is_enabled() const { return config_.enabled; }

    void set_database_region(const std::string& database, const std::string& region);
    void set_tenant_rules(const std::string& tenant_id, std::vector<std::string> allowed_regions);

    [[nodiscard]] CheckResult check(const std::string& tenant_id, const std::string& database) const;

    [[nodiscard]] size_t database_count() const;
    [[nodiscard]] size_t tenant_rule_count() const;

private:
    Config config_;
    std::unordered_map<std::string, std::string> database_regions_;          // db → region
    std::unordered_map<std::string, std::vector<std::string>> tenant_rules_; // tenant → [regions]
    mutable std::shared_mutex mutex_;
};

} // namespace sqlproxy
