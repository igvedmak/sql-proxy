#include "policy/policy_engine.hpp"
#include <algorithm>

namespace sqlproxy {

PolicyEngine::PolicyEngine()
    : store_(std::make_shared<PolicyStore>()) {}

void PolicyEngine::load_policies(const std::vector<Policy>& policies) {
    auto new_store = build_store(policies);
    std::atomic_store_explicit(&store_, new_store, std::memory_order_release);
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
    for (const auto& table : all_tables) {
        auto result = evaluate_table(user, roles, database, table,
                                     analysis.statement_type, *store);

        if (result.decision == Decision::BLOCK) {
            // First denied table blocks entire query
            return result;
        }
    }

    // All tables allowed
    return PolicyEvaluationResult(
        Decision::ALLOW,
        "multi_table_allow",
        "All tables authorized"
    );
}

void PolicyEngine::reload_policies(const std::vector<Policy>& policies) {
    std::lock_guard<std::mutex> lock(reload_mutex_);

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

    // Filter by user/role match
    std::vector<const Policy*> user_matched_policies;
    for (const auto* policy : matching_policies) {
        if (matches_user(*policy, user, roles)) {
            user_matched_policies.push_back(policy);
        }
    }

    // No matching policies → DEFAULT DENY
    if (user_matched_policies.empty()) {
        return PolicyEvaluationResult(
            Decision::BLOCK,
            "default_deny",
            "No matching policy for table: " + table.full_name()
        );
    }

    // Resolve with specificity
    return resolve_specificity(user_matched_policies);
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

    // Sort by specificity (highest first), then by priority
    std::vector<const Policy*> sorted_policies = policies;
    std::sort(sorted_policies.begin(), sorted_policies.end(),
        [](const Policy* a, const Policy* b) {
            int spec_a = a->scope.specificity();
            int spec_b = b->scope.specificity();
            if (spec_a != spec_b) {
                return spec_a > spec_b; // Higher specificity first
            }
            return a->priority > b->priority; // Higher priority first
        });

    // Get highest specificity
    int highest_specificity = sorted_policies[0]->scope.specificity();

    // Collect all policies at highest specificity
    std::vector<const Policy*> highest_spec_policies;
    for (const auto* policy : sorted_policies) {
        if (policy->scope.specificity() == highest_specificity) {
            highest_spec_policies.push_back(policy);
        }
    }

    // At same specificity: BLOCK wins over ALLOW
    for (const auto* policy : highest_spec_policies) {
        if (policy->action == Decision::BLOCK) {
            return PolicyEvaluationResult(
                Decision::BLOCK,
                policy->name,
                policy->reason
            );
        }
    }

    // No BLOCK at highest specificity → first ALLOW wins
    for (const auto* policy : highest_spec_policies) {
        if (policy->action == Decision::ALLOW) {
            return PolicyEvaluationResult(
                Decision::ALLOW,
                policy->name,
                policy->reason
            );
        }
    }

    // Shouldn't reach here, but default deny
    return PolicyEvaluationResult(
        Decision::BLOCK,
        "default_deny",
        "No explicit ALLOW policy"
    );
}

bool PolicyEngine::matches_user(const Policy& policy, const std::string& user,
                                 const std::vector<std::string>& roles) {
    // Check exclude_roles first (takes precedence)
    if (!policy.exclude_roles.empty()) {
        for (const auto& role : roles) {
            if (policy.exclude_roles.count(role) > 0) {
                return false; // User has excluded role
            }
        }
    }

    // Check user match
    if (!policy.users.empty() && policy.users.count("*") == 0) {
        if (policy.users.count(user) == 0) {
            return false; // User not in policy
        }
    }

    // Check role match
    if (!policy.roles.empty()) {
        bool role_matched = false;
        for (const auto& role : roles) {
            if (policy.roles.count(role) > 0) {
                role_matched = true;
                break;
            }
        }
        if (!role_matched) {
            return false; // No role matched
        }
    }

    return true;
}

std::shared_ptr<PolicyEngine::PolicyStore> PolicyEngine::build_store(
    const std::vector<Policy>& policies) {

    auto store = std::make_shared<PolicyStore>();

    for (const auto& policy : policies) {
        // Wildcard user policies
        if (policy.users.empty() || policy.users.count("*") > 0) {
            store->wildcard_trie.insert(policy);
        }

        // User-specific policies
        for (const auto& user : policy.users) {
            if (user != "*") {
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
