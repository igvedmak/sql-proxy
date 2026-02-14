#pragma once

#include "policy/policy_engine.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <chrono>
#include <atomic>
#include <thread>
#include <functional>
#include <optional>
#include <condition_variable>

namespace sqlproxy {

enum class AccessRequestStatus { PENDING, APPROVED, DENIED, EXPIRED };

struct AccessRequest {
    std::string id;
    std::string user;
    std::string database;
    std::string schema;
    std::string table;
    std::vector<std::string> columns;
    std::vector<std::string> statement_types;
    uint32_t duration_hours = 24;
    std::string reason;
    AccessRequestStatus status = AccessRequestStatus::PENDING;
    std::string decided_by;
    std::string deny_reason;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point decided_at;
    std::string generated_policy_name;
};

class AccessRequestManager {
public:
    struct Config {
        bool enabled = true;
        uint32_t max_duration_hours = 168;
        uint32_t default_duration_hours = 24;
        size_t max_pending_requests = 100;
        uint32_t cleanup_interval_seconds = 60;
    };

    AccessRequestManager(
        Config config,
        std::shared_ptr<PolicyEngine> policy_engine,
        std::function<std::vector<Policy>()> get_base_policies);

    ~AccessRequestManager();

    AccessRequestManager(const AccessRequestManager&) = delete;
    AccessRequestManager& operator=(const AccessRequestManager&) = delete;

    [[nodiscard]] std::string submit(
        const std::string& user,
        const std::string& database,
        const std::string& schema,
        const std::string& table,
        const std::vector<std::string>& columns,
        const std::vector<std::string>& statement_types,
        uint32_t duration_hours,
        const std::string& reason);

    [[nodiscard]] bool approve(const std::string& request_id,
                               const std::string& admin);

    [[nodiscard]] bool deny(const std::string& request_id,
                            const std::string& admin,
                            const std::string& reason);

    [[nodiscard]] std::vector<AccessRequest> get_pending() const;
    [[nodiscard]] std::vector<AccessRequest> get_all(size_t limit = 100) const;
    [[nodiscard]] std::optional<AccessRequest> get(const std::string& id) const;

    struct Stats {
        size_t total_requests = 0;
        size_t pending = 0;
        size_t approved = 0;
        size_t denied = 0;
        size_t expired = 0;
        size_t active_temp_policies = 0;
    };
    [[nodiscard]] Stats get_stats() const;

    void start();
    void stop();

private:
    Config config_;
    std::shared_ptr<PolicyEngine> policy_engine_;
    std::function<std::vector<Policy>()> get_base_policies_;

    std::unordered_map<std::string, AccessRequest> requests_;
    mutable std::shared_mutex mutex_;
    std::atomic<uint64_t> total_requests_{0};

    std::thread cleanup_thread_;
    std::atomic<bool> running_{false};
    std::mutex cleanup_mutex_;
    std::condition_variable cleanup_cv_;

    void cleanup_loop();
    void reload_policies_with_temp();
    [[nodiscard]] Policy create_temp_policy(const AccessRequest& req) const;
};

} // namespace sqlproxy
