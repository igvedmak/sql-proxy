#include "finops/cost_tracker.hpp"
#include "core/utils.hpp"

#include <algorithm>
#include <format>

namespace sqlproxy {

CostTracker::CostTracker(Config config)
    : config_(std::move(config)) {}

void CostTracker::record(const std::string& user, double cost,
                         uint64_t estimated_rows, const std::string& sql) {
    total_recorded_.fetch_add(1, std::memory_order_relaxed);

    std::unique_lock lock(mutex_);

    auto& uc = user_costs_[user];
    maybe_reset_windows(uc);

    uc.cost_today += cost;
    uc.cost_this_hour += cost;
    ++uc.queries_today;
    ++uc.queries_this_hour;

    // Track top queries
    TopQuery tq;
    tq.user = user;
    tq.cost = cost;
    tq.estimated_rows = estimated_rows;
    tq.timestamp = utils::format_timestamp(std::chrono::system_clock::now());
    tq.sql_preview = sql.size() > 200 ? sql.substr(0, 200) + "..." : sql;

    if (top_queries_.size() < config_.max_top_queries) {
        top_queries_.push_back(std::move(tq));
        std::sort(top_queries_.begin(), top_queries_.end(),
                  [](const TopQuery& a, const TopQuery& b) { return a.cost > b.cost; });
    } else if (!top_queries_.empty() && cost > top_queries_.back().cost) {
        top_queries_.back() = std::move(tq);
        std::sort(top_queries_.begin(), top_queries_.end(),
                  [](const TopQuery& a, const TopQuery& b) { return a.cost > b.cost; });
    }
}

std::string CostTracker::check_budget(const std::string& user) const {
    std::shared_lock lock(mutex_);

    const auto it = user_costs_.find(user);
    if (it == user_costs_.end()) return "";

    const auto budget = get_budget(user);
    const auto& uc = it->second;

    if (budget.daily_limit > 0 && uc.cost_today >= budget.daily_limit) {
        // Cast away constness for atomic increment (atomics are always safe)
        const_cast<CostTracker*>(this)->budget_rejections_.fetch_add(1, std::memory_order_relaxed);
        return std::format("Daily cost budget exceeded (used: {:.1f}, limit: {:.1f})",
                           uc.cost_today, budget.daily_limit);
    }
    if (budget.hourly_limit > 0 && uc.cost_this_hour >= budget.hourly_limit) {
        const_cast<CostTracker*>(this)->budget_rejections_.fetch_add(1, std::memory_order_relaxed);
        return std::format("Hourly cost budget exceeded (used: {:.1f}, limit: {:.1f})",
                           uc.cost_this_hour, budget.hourly_limit);
    }
    return "";
}

UserCostSummary CostTracker::get_user_summary(const std::string& user) const {
    std::shared_lock lock(mutex_);

    UserCostSummary summary;
    summary.user = user;

    const auto it = user_costs_.find(user);
    if (it != user_costs_.end()) {
        const auto& uc = it->second;
        summary.cost_today = uc.cost_today;
        summary.cost_this_hour = uc.cost_this_hour;
        summary.queries_today = uc.queries_today;
        summary.queries_this_hour = uc.queries_this_hour;
    }

    const auto budget = get_budget(user);
    summary.budget_daily = budget.daily_limit;
    if (budget.daily_limit > 0) {
        summary.budget_used_pct = (summary.cost_today / budget.daily_limit) * 100.0;
    }

    return summary;
}

std::vector<UserCostSummary> CostTracker::get_all_summaries() const {
    std::shared_lock lock(mutex_);

    std::vector<UserCostSummary> result;
    result.reserve(user_costs_.size());

    for (const auto& [user, uc] : user_costs_) {
        UserCostSummary s;
        s.user = user;
        s.cost_today = uc.cost_today;
        s.cost_this_hour = uc.cost_this_hour;
        s.queries_today = uc.queries_today;
        s.queries_this_hour = uc.queries_this_hour;

        const auto budget = get_budget(user);
        s.budget_daily = budget.daily_limit;
        if (budget.daily_limit > 0) {
            s.budget_used_pct = (s.cost_today / budget.daily_limit) * 100.0;
        }

        result.emplace_back(std::move(s));
    }

    return result;
}

std::vector<TopQuery> CostTracker::get_top_queries(size_t limit) const {
    std::shared_lock lock(mutex_);

    if (limit >= top_queries_.size()) return top_queries_;
    return std::vector<TopQuery>(top_queries_.begin(), top_queries_.begin() + limit);
}

CostTracker::Stats CostTracker::get_stats() const {
    std::shared_lock lock(mutex_);
    return {
        total_recorded_.load(std::memory_order_relaxed),
        budget_rejections_.load(std::memory_order_relaxed),
        user_costs_.size()
    };
}

void CostTracker::maybe_reset_windows(UserCosts& uc) const {
    const auto now = std::chrono::system_clock::now();
    const auto time_t = std::chrono::system_clock::to_time_t(now);
    struct tm tm;
    gmtime_r(&time_t, &tm);

    const int day = tm.tm_yday;
    const int hour = tm.tm_hour;

    if (uc.today_day != day) {
        uc.cost_today = 0.0;
        uc.queries_today = 0;
        uc.today_day = day;
        // Also reset hourly when day changes
        uc.cost_this_hour = 0.0;
        uc.queries_this_hour = 0;
        uc.current_hour = hour;
    } else if (uc.current_hour != hour) {
        uc.cost_this_hour = 0.0;
        uc.queries_this_hour = 0;
        uc.current_hour = hour;
    }
}

CostBudget CostTracker::get_budget(const std::string& user) const {
    const auto it = config_.user_budgets.find(user);
    if (it != config_.user_budgets.end()) return it->second;
    return config_.default_budget;
}

} // namespace sqlproxy
