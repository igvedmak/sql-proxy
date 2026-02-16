#pragma once

#include "core/types.hpp"
#include "policy/policy_trie.hpp"
#include "analyzer/sql_analyzer.hpp"
#include <memory>
#include <atomic>
#include <mutex>
#include <vector>

namespace sqlproxy {

/**
 * @brief Policy Engine - Authorization gate
 *
 * Evaluates whether a user is authorized to execute a statement
 * based on hierarchical policies with specificity resolution.
 *
 * Resolution algorithm:
 * 1. Collect ALL matching policies (user/role + scope + statement type)
 * 2. Sort by specificity (highest first)
 * 3. At highest specificity: BLOCK wins over ALLOW
 * 4. No matching policies → DEFAULT DENY
 *
 * Specificity scoring:
 * - table specified:    +100
 * - schema specified:   +10
 * - database specified: +1
 *
 * Examples:
 * - app.public.customers = 111 (most specific)
 * - app.public.*         = 110
 * - app.*.*              = 100
 * - *.*.*                = 0   (least specific)
 *
 * Multi-table queries:
 * - ALL tables must be allowed
 * - ANY table denied → entire query denied
 *
 * Thread-safety: Hot-reloadable via RCU (atomic shared_ptr)
 */
class PolicyEngine {
public:
    /**
     * @brief Construct policy engine
     */
    PolicyEngine();

    /**
     * @brief Load policies into engine
     * @param policies Vector of policies to load
     */
    void load_policies(const std::vector<Policy>& policies);

    /**
     * @brief Evaluate query against policies
     * @param user User identifier
     * @param roles User roles
     * @param analysis Analysis result from SQL analyzer
     * @return Policy evaluation result
     */
    [[nodiscard]] PolicyEvaluationResult evaluate(
        const std::string& user,
        const std::vector<std::string>& roles,
        const std::string& database,
        const AnalysisResult& analysis) const;

    /**
     * @brief Evaluate column-level access for query results
     * @param user User identifier
     * @param roles User roles
     * @param database Database name
     * @param analysis Analysis result from SQL analyzer
     * @param column_names Result column names
     * @return Per-column decisions (ALLOW/BLOCK + masking)
     */
    [[nodiscard]] std::vector<ColumnPolicyDecision> evaluate_columns(
        const std::string& user,
        const std::vector<std::string>& roles,
        const std::string& database,
        const AnalysisResult& analysis,
        const std::vector<std::string>& column_names) const;

    /**
     * @brief Hot reload policies (RCU update)
     * @param policies New policy set
     */
    void reload_policies(const std::vector<Policy>& policies);

    /**
     * @brief Get current policy count
     */
    [[nodiscard]] size_t policy_count() const;

    /**
     * @brief Get loaded policies (for dashboard/admin)
     */
    [[nodiscard]] const std::vector<Policy>& get_policies() const;

    /**
     * @brief Clear all policies
     */
    void clear();

private:
    /**
     * @brief Policy store with tries per user/role
     */
    struct PolicyStore {
        std::unordered_map<std::string, PolicyTrie> user_tries;  // user → trie
        std::unordered_map<std::string, PolicyTrie> role_tries;  // role → trie
        PolicyTrie wildcard_trie;                                 // "*" users
    };

    /**
     * @brief Evaluate single table access
     * @param user User identifier
     * @param roles User roles
     * @param table Table reference
     * @param stmt_type Statement type
     * @param store Policy store
     * @return Evaluation result
     */
    PolicyEvaluationResult evaluate_table(
        const std::string& user,
        const std::vector<std::string>& roles,
        const std::string& database,
        const TableRef& table,
        StatementType stmt_type,
        const PolicyStore& store) const;

    /**
     * @brief Resolve policies with specificity
     * @param policies Matching policies
     * @return Final decision
     */
    PolicyEvaluationResult resolve_specificity(
        const std::vector<const Policy*>& policies) const;

    /**
     * @brief Check if user matches policy
     */
    static bool matches_user(const Policy& policy, const std::string& user,
                             const std::vector<std::string>& roles);

    /**
     * @brief Build policy store from policy list
     */
    static std::shared_ptr<PolicyStore> build_store(const std::vector<Policy>& policies);

    // RCU: Readers load shared_ptr atomically, writers build offline and swap
    // C++20 atomic<shared_ptr> — proper lock-free or efficient locking
    std::atomic<std::shared_ptr<PolicyStore>> store_;

    // Raw policies for admin/dashboard access
    std::vector<Policy> policies_;

    // Mutex for reload (single writer)
    mutable std::mutex reload_mutex_;
};

} // namespace sqlproxy
