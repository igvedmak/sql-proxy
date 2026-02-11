#include "tenant/data_residency.hpp"

#include <algorithm>
#include <format>
#include <mutex>

namespace sqlproxy {

DataResidencyEnforcer::DataResidencyEnforcer() : DataResidencyEnforcer(Config{}) {}

DataResidencyEnforcer::DataResidencyEnforcer(Config config)
    : config_(std::move(config)) {}

void DataResidencyEnforcer::set_database_region(const std::string& database, const std::string& region) {
    std::unique_lock lock(mutex_);
    database_regions_[database] = region;
}

void DataResidencyEnforcer::set_tenant_rules(const std::string& tenant_id, std::vector<std::string> allowed_regions) {
    std::unique_lock lock(mutex_);
    tenant_rules_[tenant_id] = std::move(allowed_regions);
}

DataResidencyEnforcer::CheckResult DataResidencyEnforcer::check(
    const std::string& tenant_id, const std::string& database) const {

    if (!config_.enabled) {
        return {true, "", ""};
    }

    std::shared_lock lock(mutex_);

    // Find the database's region
    const auto db_it = database_regions_.find(database);
    if (db_it == database_regions_.end()) {
        // No region configured for this database — allow by default
        return {true, "", ""};
    }
    const auto& db_region = db_it->second;

    // Find the tenant's allowed regions
    auto tenant_it = tenant_rules_.find(tenant_id);
    if (tenant_it == tenant_rules_.end()) {
        // No residency rules for this tenant — allow by default
        return {true, db_region, ""};
    }

    const auto& allowed = tenant_it->second;
    if (allowed.empty()) {
        return {true, db_region, ""};
    }

    // Check if db_region is in allowed regions
    const bool found = std::find(allowed.begin(), allowed.end(), db_region) != allowed.end();
    if (found) {
        return {true, db_region, ""};
    }

    return {false, db_region, std::format(
        "Data residency violation: tenant '{}' is restricted to regions [{}] but database '{}' is in region '{}'",
        tenant_id,
        [&]() {
            std::string r;
            for (size_t i = 0; i < allowed.size(); ++i) {
                if (i > 0) r += ", ";
                r += allowed[i];
            }
            return r;
        }(),
        database, db_region)};
}

size_t DataResidencyEnforcer::database_count() const {
    std::shared_lock lock(mutex_);
    return database_regions_.size();
}

size_t DataResidencyEnforcer::tenant_rule_count() const {
    std::shared_lock lock(mutex_);
    return tenant_rules_.size();
}

} // namespace sqlproxy
