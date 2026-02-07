#include "policy/policy_trie.hpp"
#include <algorithm>

namespace sqlproxy {

// ============================================================================
// PolicyTrieNode Implementation
// ============================================================================

void PolicyTrieNode::add_policy(const Policy& policy) {
    policies_.push_back(policy);
}

PolicyTrieNode* PolicyTrieNode::get_or_create_child(const std::string& key) {
    // try_emplace: 1 hash op instead of find + operator[] = 2 hash ops
    auto [it, inserted] = children_.try_emplace(key);
    if (inserted) {
        it->second = std::make_unique<PolicyTrieNode>();
    }
    return it->second.get();
}

const PolicyTrieNode* PolicyTrieNode::get_child(const std::string& key) const {
    auto it = children_.find(key);
    return it != children_.end() ? it->second.get() : nullptr;
}

bool PolicyTrieNode::has_child(const std::string& key) const {
    return children_.contains(key);
}

// ============================================================================
// PolicyTrie Implementation
// ============================================================================

void PolicyTrie::insert(const Policy& policy) {
    // Build path: database → schema → table
    std::vector<std::string> path;

    std::string db = policy.scope.database.value_or("*");
    std::string schema = policy.scope.schema.value_or("*");
    std::string table = policy.scope.table.value_or("*");

    path.push_back(db);
    path.push_back(schema);
    path.push_back(table);

    // Walk trie and insert at leaf
    PolicyTrieNode* current = &root_;
    for (const auto& part : path) {
        current = current->get_or_create_child(part);
    }

    current->add_policy(policy);
    ++policy_count_;
}

std::vector<const Policy*> PolicyTrie::find_matching(
    const std::string& database,
    const std::string& schema,
    const std::string& table,
    StatementType stmt_type) const {

    std::vector<const Policy*> results;

    // Build path parts
    std::vector<std::string> path_parts = {
        database.empty() ? "*" : database,
        schema.empty() ? "*" : schema,
        table.empty() ? "*" : table
    };

    // Recursively find all matching policies
    find_matching_recursive(&root_, path_parts, 0, stmt_type, results);

    return results;
}

void PolicyTrie::clear() {
    root_ = PolicyTrieNode();
    policy_count_ = 0;
}

void PolicyTrie::find_matching_recursive(
    const PolicyTrieNode* node,
    const std::vector<std::string>& path_parts,
    size_t depth,
    StatementType stmt_type,
    std::vector<const Policy*>& results) const {

    if (!node) {
        return;
    }

    // If we've reached the leaf level (depth 3), collect policies
    if (depth == path_parts.size()) {
        for (const auto& policy : node->get_policies()) {
            if (matches_statement_type(policy, stmt_type)) {
                results.push_back(&policy);
            }
        }
        return;
    }

    const std::string& current_part = path_parts[depth];

    // Try exact match
    const PolicyTrieNode* exact_child = node->get_child(current_part);
    if (exact_child) {
        find_matching_recursive(exact_child, path_parts, depth + 1, stmt_type, results);
    }

    // Try wildcard match (if not already wildcard)
    if (current_part != "*") {
        const PolicyTrieNode* wildcard_child = node->get_child("*");
        if (wildcard_child) {
            find_matching_recursive(wildcard_child, path_parts, depth + 1, stmt_type, results);
        }
    }
}

bool PolicyTrie::matches_statement_type(const Policy& policy, StatementType stmt_type) {
    // Empty operations set = matches all
    if (policy.scope.operations.empty()) {
        return true;
    }

    return policy.scope.operations.contains(stmt_type);
}

} // namespace sqlproxy
