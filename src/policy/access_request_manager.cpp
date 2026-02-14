#include "policy/access_request_manager.hpp"
#include "core/utils.hpp"

#include <format>
#include <algorithm>

namespace sqlproxy {

AccessRequestManager::AccessRequestManager(
    Config config,
    std::shared_ptr<PolicyEngine> policy_engine,
    std::function<std::vector<Policy>()> get_base_policies)
    : config_(std::move(config)),
      policy_engine_(std::move(policy_engine)),
      get_base_policies_(std::move(get_base_policies)) {}

AccessRequestManager::~AccessRequestManager() {
    stop();
}

std::string AccessRequestManager::submit(
    const std::string& user,
    const std::string& database,
    const std::string& schema,
    const std::string& table,
    const std::vector<std::string>& columns,
    const std::vector<std::string>& statement_types,
    uint32_t duration_hours,
    const std::string& reason) {

    if (duration_hours == 0) duration_hours = config_.default_duration_hours;
    if (duration_hours > config_.max_duration_hours) duration_hours = config_.max_duration_hours;

    std::unique_lock lock(mutex_);

    // Check pending count
    size_t pending_count = 0;
    for (const auto& [id, req] : requests_) {
        if (req.status == AccessRequestStatus::PENDING) ++pending_count;
    }
    if (pending_count >= config_.max_pending_requests) {
        return "";  // Caller should check empty return
    }

    AccessRequest req;
    req.id = "req-" + utils::generate_uuid().substr(0, 8);
    req.user = user;
    req.database = database;
    req.schema = schema;
    req.table = table;
    req.columns = columns;
    req.statement_types = statement_types;
    req.duration_hours = duration_hours;
    req.reason = reason;
    req.status = AccessRequestStatus::PENDING;
    req.created_at = std::chrono::system_clock::now();

    std::string id = req.id;
    requests_.emplace(id, std::move(req));
    total_requests_.fetch_add(1, std::memory_order_relaxed);

    return id;
}

bool AccessRequestManager::approve(const std::string& request_id,
                                   const std::string& admin) {
    std::unique_lock lock(mutex_);

    auto it = requests_.find(request_id);
    if (it == requests_.end()) return false;
    if (it->second.status != AccessRequestStatus::PENDING) return false;

    it->second.status = AccessRequestStatus::APPROVED;
    it->second.decided_by = admin;
    it->second.decided_at = std::chrono::system_clock::now();

    const auto policy = create_temp_policy(it->second);
    it->second.generated_policy_name = policy.name;

    lock.unlock();
    reload_policies_with_temp();

    return true;
}

bool AccessRequestManager::deny(const std::string& request_id,
                                const std::string& admin,
                                const std::string& reason) {
    std::unique_lock lock(mutex_);

    auto it = requests_.find(request_id);
    if (it == requests_.end()) return false;
    if (it->second.status != AccessRequestStatus::PENDING) return false;

    it->second.status = AccessRequestStatus::DENIED;
    it->second.decided_by = admin;
    it->second.decided_at = std::chrono::system_clock::now();
    it->second.deny_reason = reason;

    return true;
}

std::vector<AccessRequest> AccessRequestManager::get_pending() const {
    std::shared_lock lock(mutex_);
    std::vector<AccessRequest> result;
    for (const auto& [id, req] : requests_) {
        if (req.status == AccessRequestStatus::PENDING) {
            result.push_back(req);
        }
    }
    return result;
}

std::vector<AccessRequest> AccessRequestManager::get_all(size_t limit) const {
    std::shared_lock lock(mutex_);
    std::vector<AccessRequest> result;
    result.reserve(std::min(limit, requests_.size()));
    for (const auto& [id, req] : requests_) {
        if (result.size() >= limit) break;
        result.push_back(req);
    }
    return result;
}

std::optional<AccessRequest> AccessRequestManager::get(const std::string& id) const {
    std::shared_lock lock(mutex_);
    const auto it = requests_.find(id);
    if (it == requests_.end()) return std::nullopt;
    return it->second;
}

AccessRequestManager::Stats AccessRequestManager::get_stats() const {
    std::shared_lock lock(mutex_);
    Stats stats;
    stats.total_requests = total_requests_.load(std::memory_order_relaxed);

    const auto now = std::chrono::system_clock::now();
    for (const auto& [id, req] : requests_) {
        switch (req.status) {
            case AccessRequestStatus::PENDING: ++stats.pending; break;
            case AccessRequestStatus::APPROVED: {
                ++stats.approved;
                // Check if still active
                if (req.decided_at + std::chrono::hours(req.duration_hours) > now) {
                    ++stats.active_temp_policies;
                }
                break;
            }
            case AccessRequestStatus::DENIED: ++stats.denied; break;
            case AccessRequestStatus::EXPIRED: ++stats.expired; break;
        }
    }
    return stats;
}

void AccessRequestManager::start() {
    if (running_.exchange(true)) return;
    cleanup_thread_ = std::thread([this] { cleanup_loop(); });
}

void AccessRequestManager::stop() {
    if (!running_.exchange(false)) return;
    {
        std::lock_guard lock(cleanup_mutex_);
        cleanup_cv_.notify_all();
    }
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
}

void AccessRequestManager::cleanup_loop() {
    while (running_.load()) {
        {
            std::unique_lock lock(cleanup_mutex_);
            cleanup_cv_.wait_for(lock,
                std::chrono::seconds(config_.cleanup_interval_seconds),
                [this] { return !running_.load(); });
        }
        if (!running_.load()) break;

        bool any_expired = false;
        const auto now = std::chrono::system_clock::now();

        {
            std::unique_lock lock(mutex_);

            // Expire approved requests whose time has passed
            for (auto& [id, req] : requests_) {
                if (req.status == AccessRequestStatus::APPROVED) {
                    const auto valid_until = req.decided_at + std::chrono::hours(req.duration_hours);
                    if (now > valid_until) {
                        req.status = AccessRequestStatus::EXPIRED;
                        any_expired = true;
                    }
                }
            }

            // Clean up old denied/expired requests (>7 days)
            const auto cutoff = now - std::chrono::hours(168);
            for (auto it = requests_.begin(); it != requests_.end(); ) {
                if ((it->second.status == AccessRequestStatus::DENIED ||
                     it->second.status == AccessRequestStatus::EXPIRED) &&
                    it->second.created_at < cutoff) {
                    it = requests_.erase(it);
                } else {
                    ++it;
                }
            }
        }

        if (any_expired) {
            reload_policies_with_temp();
        }
    }
}

void AccessRequestManager::reload_policies_with_temp() {
    auto policies = get_base_policies_();
    const auto now = std::chrono::system_clock::now();

    {
        std::shared_lock lock(mutex_);
        for (const auto& [id, req] : requests_) {
            if (req.status != AccessRequestStatus::APPROVED) continue;
            const auto valid_until = req.decided_at + std::chrono::hours(req.duration_hours);
            if (now > valid_until) continue;
            policies.push_back(create_temp_policy(req));
        }
    }

    policy_engine_->reload_policies(policies);
}

Policy AccessRequestManager::create_temp_policy(const AccessRequest& req) const {
    Policy p;
    p.name = "access_grant_" + req.id;
    p.priority = 95;
    p.action = Decision::ALLOW;
    p.scope.database = req.database;
    if (!req.schema.empty()) p.scope.schema = req.schema;
    p.scope.table = req.table;
    // Note: columns from request are for audit only, not set in scope
    // (column-level policies are skipped in table enforcement)
    for (const auto& st : req.statement_types) {
        p.scope.operations.insert(statement_type_from_string(st));
    }
    p.users = {req.user};
    p.reason = std::format("Temporary access granted by {} (request {})",
                           req.decided_by, req.id);
    p.valid_from = req.decided_at;
    p.valid_until = req.decided_at + std::chrono::hours(req.duration_hours);
    return p;
}

} // namespace sqlproxy
