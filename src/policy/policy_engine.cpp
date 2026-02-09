#include "policy/policy_engine.hpp"
#include <algorithm>

namespace sqlproxy {
    
static const std::string kWildcardKey = "*";

PolicyEngine::PolicyEngine()
    : store_(std::make_shared<PolicyStore>()) {}

void PolicyEngine::load_policies(const std::vector<Policy>& policies) {
    policies_ = policies;
    auto new_store = build_store(policies);
    std::atomic_store_explicit(&store_, new_store, std::memory_order_release);
}

const std::vector<Policy>& PolicyEngine::get_policies() const {
    return policies_;
}

PolicyEvaluationResult PolicyEngine::evaluate(
    const std::string& user,
    const std::vector<std::string>& roles,
    const std::string& database,
    const AnalysisResult& analysis) const {

    // Load current policy store (RCU read)
    auto store = std::atomic_load_explicit(&store_, std::memory_order_acquire);

    if (!store) {
        return PolicyEvaluationResult(
            Decision::BLOCK,
            "default_deny",
            "No policies loaded - default deny"
        );
    }

    // Collect all tables that need authorization
    std::vector<TableRef> all_tables;
    all_tables.insert(all_tables.end(),
                     analysis.source_tables.begin(),
                     analysis.source_tables.end());
    all_tables.insert(all_tables.end(),
                     analysis.target_tables.begin(),
                     analysis.target_tables.end());

    if (all_tables.empty()) {
        // No tables accessed (e.g., SET, SHOW commands)
        // Allow by default for utility statements
        return PolicyEvaluationResult(
            Decision::ALLOW,
            "utility_statement",
            "Utility statement with no table access"
        );
    }

    // Multi-table evaluation: ALL must be allowed, ANY denied = entire query denied
    // Track shadow results across all tables
    bool any_shadow_blocked = false;
    std::string shadow_policy_name;

    for (const auto& table : all_tables) {
        auto result = evaluate_table(user, roles, database, table,
                                     analysis.statement_type, *store);

        // Track shadow results
        if (result.shadow_blocked && !any_shadow_blocked) {
            any_shadow_blocked = true;
            shadow_policy_name = result.shadow_policy;
        }

        if (result.decision == Decision::BLOCK) {
            // Propagate shadow info to blocked result
            result.shadow_blocked = any_shadow_blocked;
            result.shadow_policy = shadow_policy_name;
            return result;
        }
    }

    // All tables allowed
    PolicyEvaluationResult allow_result(
        Decision::ALLOW,
        "multi_table_allow",
        "All tables authorized"
    );
    allow_result.shadow_blocked = any_shadow_blocked;
    allow_result.shadow_policy = shadow_policy_name;
    return allow_result;
}

std::vector<ColumnPolicyDecision> PolicyEngine::evaluate_columns(
    const std::string& user,
    const std::vector<std::string>& roles,
    const std::string& database,
    const AnalysisResult& analysis,
    const std::vector<std::string>& column_names) const {

    auto store = std::atomic_load_explicit(&store_, std::memory_order_acquire);
    std::vector<ColumnPolicyDecision> decisions;
    decisions.reserve(column_names.size());

    if (!store) {
        for (const auto& col : column_names) {
            decisions.push_back({col, Decision::ALLOW, MaskingAction::NONE, {}});
        }
        return decisions;
    }

    // Collect column-level policies (scope.columns non-empty) from matching tables
    auto collect_column_policies = [&](const PolicyTrie& trie) -> std::vector<const Policy*> {
        std::vector<const Policy*> result;
        for (const auto& table : analysis.source_tables) {
            const std::string eff_schema = table.schema.empty() ? "public" : table.schema;
            auto matches = trie.find_matching(database, eff_schema, table.table,
                                               analysis.statement_type);
            for (const auto* p : matches) {
                if (!p->scope.columns.empty() && matches_user(*p, user, roles)) {
                    result.push_back(p);
                }
            }
        }
        return result;
    };

    std::vector<const Policy*> column_policies;
    auto user_it = store->user_tries.find(user);
    if (user_it != store->user_tries.end()) {
        auto p = collect_column_policies(user_it->second);
        column_policies.insert(column_policies.end(), p.begin(), p.end());
    }
    for (const auto& role : roles) {
        auto role_it = store->role_tries.find(role);
        if (role_it != store->role_tries.end()) {
            auto p = collect_column_policies(role_it->second);
            column_policies.insert(column_policies.end(), p.begin(), p.end());
        }
    }
    {
        auto p = collect_column_policies(store->wildcard_trie);
        column_policies.insert(column_policies.end(), p.begin(), p.end());
    }

    // No column policies at all → default ALLOW everything
    if (column_policies.empty()) {
        for (const auto& col : column_names) {
            decisions.push_back({col, Decision::ALLOW, MaskingAction::NONE, {}});
        }
        return decisions;
    }

    // For each result column, resolve best matching column policy
    for (const auto& col : column_names) {
        ColumnPolicyDecision decision;
        decision.column_name = col;
        decision.decision = Decision::ALLOW;

        const Policy* best_match = nullptr;
        int best_specificity = -1;
        int best_priority = -1;

        for (const auto* policy : column_policies) {
            bool targets_column = false;
            for (const auto& pc : policy->scope.columns) {
                if (pc == col || pc == "*") {
                    targets_column = true;
                    break;
                }
            }
            if (!targets_column) continue;

            const int spec = policy->scope.specificity();
            if (spec > best_specificity ||
                (spec == best_specificity && policy->priority > best_priority)) {
                best_specificity = spec;
                best_priority = policy->priority;
                best_match = policy;
            }
        }

        if (best_match) {
            decision.decision = best_match->action;
            decision.matched_policy = best_match->name;
            if (best_match->action == Decision::ALLOW) {
                decision.masking = best_match->masking_action;
                decision.prefix_len = best_match->masking_prefix_len;
                decision.suffix_len = best_match->masking_suffix_len;
            }
        }

        decisions.push_back(std::move(decision));
    }

    return decisions;
}

void PolicyEngine::reload_policies(const std::vector<Policy>& policies) {
    std::lock_guard<std::mutex> lock(reload_mutex_);

    policies_ = policies;
    auto new_store = build_store(policies);
    std::atomic_store_explicit(&store_, new_store, std::memory_order_release);
}

size_t PolicyEngine::policy_count() const {
    auto store = std::atomic_load_explicit(&store_, std::memory_order_acquire);
    if (!store) {
        return 0;
    }

    size_t count = 0;
    for (const auto& [user, trie] : store->user_tries) {
        count += trie.size();
    }
    for (const auto& [role, trie] : store->role_tries) {
        count += trie.size();
    }
    count += store->wildcard_trie.size();

    return count;
}

void PolicyEngine::clear() {
    std::lock_guard<std::mutex> lock(reload_mutex_);
    std::atomic_store_explicit(&store_, std::make_shared<PolicyStore>(), std::memory_order_release);
}

PolicyEvaluationResult PolicyEngine::evaluate_table(
    const std::string& user,
    const std::vector<std::string>& roles,
    const std::string& database,
    const TableRef& table,
    StatementType stmt_type,
    const PolicyStore& store) const {

    std::vector<const Policy*> matching_policies;

    // Resolve effective schema: default to "public" when not specified
    // (consistent with PostgreSQL's default search_path)
    const std::string effective_schema = table.schema.empty() ? "public" : table.schema;

    // Collect from user-specific trie
    auto user_it = store.user_tries.find(user);
    if (user_it != store.user_tries.end()) {
        auto user_matches = user_it->second.find_matching(
            database,
            effective_schema,
            table.table,
            stmt_type
        );
        matching_policies.insert(matching_policies.end(),
                                user_matches.begin(), user_matches.end());
    }

    // Collect from role-specific tries
    for (const auto& role : roles) {
        auto role_it = store.role_tries.find(role);
        if (role_it != store.role_tries.end()) {
            auto role_matches = role_it->second.find_matching(
                database,
                effective_schema,
                table.table,
                stmt_type
            );
            matching_policies.insert(matching_policies.end(),
                                    role_matches.begin(), role_matches.end());
        }
    }

    // Collect from wildcard trie
    auto wildcard_matches = store.wildcard_trie.find_matching(
        database,
        effective_schema,
        table.table,
        stmt_type
    );
    matching_policies.insert(matching_policies.end(),
                            wildcard_matches.begin(), wildcard_matches.end());

    // Filter by user/role match, skipping column-level policies
    // Partition into enforcement vs shadow policies
    std::vector<const Policy*> enforcement_policies;
    std::vector<const Policy*> shadow_policies;
    for (const auto* policy : matching_policies) {
        if (!policy->scope.columns.empty()) continue;
        if (!matches_user(*policy, user, roles)) continue;

        if (policy->shadow) {
            shadow_policies.push_back(policy);
        } else {
            enforcement_policies.push_back(policy);
        }
    }

    // Resolve enforcement decision
    PolicyEvaluationResult result;
    if (enforcement_policies.empty()) {
        result = PolicyEvaluationResult(
            Decision::BLOCK,
            "default_deny",
            "No matching policy for table: " + table.full_name()
        );
    } else {
        result = resolve_specificity(enforcement_policies);
    }

    // Evaluate shadow policies (log-only, never changes actual decision)
    if (!shadow_policies.empty()) {
        auto shadow_result = resolve_specificity(shadow_policies);
        if (shadow_result.decision == Decision::BLOCK) {
            result.shadow_blocked = true;
            result.shadow_policy = shadow_result.matched_policy;
        }
    }

    return result;
}

PolicyEvaluationResult PolicyEngine::resolve_specificity(
    const std::vector<const Policy*>& policies) const {

    if (policies.empty()) {
        return PolicyEvaluationResult(
            Decision::BLOCK,
            "default_deny",
            "No policies matched"
        );
    }

    // Cache specificity per policy to avoid recomputation (was called ~2*N*logN + 2*N times)
    struct RankedPolicy {
        const Policy* policy;
        int specificity;
    };

    std::vector<RankedPolicy> ranked;
    ranked.reserve(policies.size());
    for (const auto* p : policies) {
        ranked.push_back({p, p->scope.specificity()});
    }

    std::sort(ranked.begin(), ranked.end(),
        [](const RankedPolicy& a, const RankedPolicy& b) {
            if (a.specificity != b.specificity) {
                return a.specificity > b.specificity;
            }
            return a.policy->priority > b.policy->priority;
        });

    const int highest = ranked[0].specificity;

    // Single pass: BLOCK wins at highest specificity, track first ALLOW as fallback
    const Policy* first_allow = nullptr;
    for (const auto& [policy, spec] : ranked) {
        if (spec != highest) break;
        if (policy->action == Decision::BLOCK) {
            return PolicyEvaluationResult(Decision::BLOCK, policy->name, policy->reason);
        }
        if (!first_allow && policy->action == Decision::ALLOW) {
            first_allow = policy;
        }
    }

    if (first_allow) {
        return PolicyEvaluationResult(Decision::ALLOW, first_allow->name, first_allow->reason);
    }

    return PolicyEvaluationResult(
        Decision::BLOCK,
        "default_deny",
        "No explicit ALLOW policy"
    );
}

bool PolicyEngine::matches_user(const Policy& policy, const std::string& user,
                                 const std::vector<std::string>& roles) {
    // Early exit: Check exclude_roles first (takes precedence)
    for (const auto& role : roles) {
        if (policy.exclude_roles.contains(role)) {
            return false;
        }
    }

    // Check user match
    if (!policy.users.empty() && !policy.users.contains(kWildcardKey) && !policy.users.contains(user)) {
        return false;
    }

    // Check role match - early return when found
    if (!policy.roles.empty()) {
        for (const auto& role : roles) {
            if (policy.roles.contains(role)) return true;
        }
        return false;
    }

    return true;
}

std::shared_ptr<PolicyEngine::PolicyStore> PolicyEngine::build_store(
    const std::vector<Policy>& policies) {

    auto store = std::make_shared<PolicyStore>();

    for (const auto& policy : policies) {
        // Wildcard user policies
        if (policy.users.empty() || policy.users.contains(kWildcardKey)) {
            store->wildcard_trie.insert(policy);
        }

        // User-specific policies
        for (const auto& user : policy.users) {
            if (user != kWildcardKey) {
                store->user_tries[user].insert(policy);
            }
        }

        // Role-specific policies
        for (const auto& role : policy.roles) {
            store->role_tries[role].insert(policy);
        }
    }

    return store;
}

} // namespace sqlproxy
