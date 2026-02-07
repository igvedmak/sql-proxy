#pragma once

#include "core/types.hpp"
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace sqlproxy {

/**
 * @brief Radix Trie node for hierarchical policy storage
 *
 * Hierarchy: database → schema → table
 * Wildcard "*" matches any value at that level
 *
 * Example paths:
 * - "*.*.*"              → specificity 0   (match all)
 * - "app.*.*"            → specificity 100 (database level)
 * - "app.public.*"       → specificity 110 (schema level)
 * - "app.public.users"   → specificity 111 (table level)
 */
class PolicyTrieNode {
public:
    PolicyTrieNode() = default;

    /**
     * @brief Add policy at this node
     */
    void add_policy(const Policy& policy);

    /**
     * @brief Get policies at this node
     */
    const std::vector<Policy>& get_policies() const { return policies_; }

    /**
     * @brief Check if node has policies
     */
    bool has_policies() const { return !policies_.empty(); }

    /**
     * @brief Get or create child node
     */
    PolicyTrieNode* get_or_create_child(const std::string& key);

    /**
     * @brief Get child node (read-only)
     */
    const PolicyTrieNode* get_child(const std::string& key) const;

    /**
     * @brief Check if child exists
     */
    bool has_child(const std::string& key) const;

private:
    std::unordered_map<std::string, std::unique_ptr<PolicyTrieNode>> children_;
    std::vector<Policy> policies_;
};

/**
 * @brief Radix Trie for policy storage and lookup
 *
 * Provides O(1) policy lookup by walking the trie path:
 * database → schema → table (at most 3 lookups)
 *
 * Supports wildcard matching at each level.
 *
 * Performance: ~100-400ns for lookup (depending on specificity)
 */
class PolicyTrie {
public:
    PolicyTrie() = default;

    /**
     * @brief Insert policy into trie
     * @param policy Policy to insert
     */
    void insert(const Policy& policy);

    /**
     * @brief Find all matching policies for a table access
     * @param database Database name (empty = wildcard)
     * @param schema Schema name (empty = wildcard)
     * @param table Table name (empty = wildcard)
     * @param stmt_type Statement type to match
     * @return Vector of matching policies
     */
    std::vector<const Policy*> find_matching(
        const std::string& database,
        const std::string& schema,
        const std::string& table,
        StatementType stmt_type) const;

    /**
     * @brief Clear all policies
     */
    void clear();

    /**
     * @brief Get total policy count
     */
    size_t size() const { return policy_count_; }

private:
    /**
     * @brief Recursively find matching policies
     * @param node Current node
     * @param path_parts Remaining path parts [database, schema, table]
     * @param depth Current depth (0=database, 1=schema, 2=table)
     * @param stmt_type Statement type filter
     * @param results Output vector
     */
    void find_matching_recursive(
        const PolicyTrieNode* node,
        const std::vector<std::string>& path_parts,
        size_t depth,
        StatementType stmt_type,
        std::vector<const Policy*>& results) const;

    /**
     * @brief Check if policy matches statement type
     */
    static bool matches_statement_type(const Policy& policy, StatementType stmt_type);

    PolicyTrieNode root_;
    size_t policy_count_ = 0;
};

} // namespace sqlproxy
