#pragma once

#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <chrono>
#include <vector>
#include <atomic>

namespace sqlproxy {

struct UserCostSummary {
    std::string user;
    double cost_today = 0.0;
    double cost_this_hour = 0.0;
    uint64_t queries_today = 0;
    uint64_t queries_this_hour = 0;
    double budget_daily = 0.0;
    double budget_used_pct = 0.0;
};

struct CostBudget {
    double daily_limit = 0.0;
    double hourly_limit = 0.0;
};

struct TopQuery {
    std::string user;
    std::string sql_preview;
    double cost;
    uint64_t estimated_rows;
    std::string timestamp;
};

class CostTracker {
public:
    struct Config {
        bool enabled = true;
        size_t max_top_queries = 50;
        CostBudget default_budget;
        std::unordered_map<std::string, CostBudget> user_budgets;
    };

    CostTracker() = default;
    explicit CostTracker(Config config);

    void record(const std::string& user, double cost,
                uint64_t estimated_rows, const std::string& sql);

    [[nodiscard]] std::string check_budget(const std::string& user) const;

    [[nodiscard]] UserCostSummary get_user_summary(const std::string& user) const;
    [[nodiscard]] std::vector<UserCostSummary> get_all_summaries() const;
    [[nodiscard]] std::vector<TopQuery> get_top_queries(size_t limit = 20) const;

    struct Stats {
        uint64_t total_recorded = 0;
        uint64_t budget_rejections = 0;
        size_t tracked_users = 0;
    };
    [[nodiscard]] Stats get_stats() const;

private:
    Config config_;

    struct UserCosts {
        double cost_today = 0.0;
        double cost_this_hour = 0.0;
        uint64_t queries_today = 0;
        uint64_t queries_this_hour = 0;
        int today_day = 0;
        int current_hour = 0;
    };

    std::unordered_map<std::string, UserCosts> user_costs_;
    std::vector<TopQuery> top_queries_;
    mutable std::shared_mutex mutex_;
    std::atomic<uint64_t> total_recorded_{0};
    std::atomic<uint64_t> budget_rejections_{0};

    void maybe_reset_windows(UserCosts& uc) const;
    [[nodiscard]] CostBudget get_budget(const std::string& user) const;
};

} // namespace sqlproxy
