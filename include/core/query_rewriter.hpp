#pragma once

#include "core/types.hpp"
#include "analyzer/sql_analyzer.hpp"

#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace sqlproxy {

/**
 * @brief Query rewriter - RLS injection + enforce_limit
 *
 * Applies query transformations between policy evaluation and execution:
 * 1. Row-Level Security: Injects WHERE clauses based on user attributes
 * 2. Enforce Limit: Adds LIMIT N to SELECT queries without one
 *
 * Thread-safety: RCU (rules stored in shared_ptr, swapped atomically on reload)
 */
class QueryRewriter {
public:
    QueryRewriter() = default;

    /**
     * @brief Load rules
     */
    void load_rules(const std::vector<RlsRule>& rls_rules,
                    const std::vector<RewriteRule>& rewrite_rules);

    /**
     * @brief Hot-reload rules (thread-safe)
     */
    void reload_rules(const std::vector<RlsRule>& rls_rules,
                      const std::vector<RewriteRule>& rewrite_rules);

    /**
     * @brief Rewrite SQL based on rules
     * @return Rewritten SQL (empty if no changes)
     */
    [[nodiscard]] std::string rewrite(
        const std::string& sql,
        const std::string& user,
        const std::vector<std::string>& roles,
        const std::string& database,
        const AnalysisResult& analysis,
        const std::unordered_map<std::string, std::string>& user_attributes) const;

private:
    struct RuleStore {
        std::vector<RlsRule> rls_rules;
        std::vector<RewriteRule> rewrite_rules;
    };

    static std::string expand_template(
        const std::string& condition,
        const std::string& user,
        const std::vector<std::string>& roles,
        const std::unordered_map<std::string, std::string>& attributes);

    static std::string inject_where(const std::string& sql, const std::string& condition);
    static std::string enforce_limit(const std::string& sql, int limit_value);

    static bool matches_user_or_role(
        const std::vector<std::string>& rule_users,
        const std::vector<std::string>& rule_roles,
        const std::string& user,
        const std::vector<std::string>& user_roles);

    std::shared_ptr<RuleStore> store_;
    mutable std::shared_mutex mutex_;
};

} // namespace sqlproxy
