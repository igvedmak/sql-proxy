#pragma once

#include "core/types.hpp"

namespace sqlproxy {

// ============================================================================
// Policy Types
// ============================================================================

struct PolicyScope {
    std::optional<std::string> database;
    std::optional<std::string> schema;
    std::optional<std::string> table;
    std::vector<std::string> columns;               // Column-level ACL (empty = all columns)
    std::unordered_set<StatementType> operations;

    // Specificity via bitmask: columns(bit3) > table(bit2) > schema(bit1) > database(bit0)
    // Produces values 0b0000..0b1111 preserving hierarchical ordering
    static constexpr int kDatabaseBit = 0;
    static constexpr int kSchemaBit   = 1;
    static constexpr int kTableBit    = 2;
    static constexpr int kColumnBit   = 3;

    int specificity() const {
        int score = 0;
        if (database.has_value())  score |= (1 << kDatabaseBit);
        if (schema.has_value())    score |= (1 << kSchemaBit);
        if (table.has_value())     score |= (1 << kTableBit);
        if (!columns.empty())      score |= (1 << kColumnBit);
        return score;
    }
};

struct Policy {
    std::string name;
    int priority;                           // Higher = evaluated first
    Decision action;                        // ALLOW or BLOCK
    PolicyScope scope;
    std::unordered_set<std::string> users;  // Empty = all users, "*" = wildcard
    std::unordered_set<std::string> roles;  // Role-based matching
    std::unordered_set<std::string> exclude_roles;  // Roles to exclude (e.g., users=["*"] exclude_roles=["admin"])
    std::string reason;                     // Human-readable explanation for audit logs

    // Masking (for column-level ALLOW policies)
    MaskingAction masking_action = MaskingAction::NONE;
    int masking_prefix_len = 3;             // For PARTIAL: chars to show at start
    int masking_suffix_len = 3;             // For PARTIAL: chars to show at end

    // Shadow mode: log decision but don't enforce
    bool shadow = false;

    Policy() : priority(0), action(Decision::BLOCK) {}

    bool matches_user(const std::string& user) const {
        return users.empty() ||
               users.contains("*") ||
               users.contains(user);
    }
};

struct PolicyEvaluationResult {
    Decision decision;
    std::string matched_policy;     // Policy name that made the decision
    std::string reason;             // Human-readable reason

    // Shadow mode: a shadow policy would have blocked, but didn't enforce
    bool shadow_blocked = false;
    std::string shadow_policy;

    PolicyEvaluationResult() : decision(Decision::BLOCK) {}
    PolicyEvaluationResult(Decision d, std::string p, std::string r)
        : decision(d), matched_policy(std::move(p)), reason(std::move(r)) {}
};

struct ColumnPolicyDecision {
    std::string column_name;
    Decision decision = Decision::ALLOW;
    MaskingAction masking = MaskingAction::NONE;
    std::string matched_policy;
    int prefix_len = 3;
    int suffix_len = 3;
};

struct MaskingRecord {
    std::string column_name;
    MaskingAction action;
    std::string matched_policy;
};

// ============================================================================
// Row-Level Security & Query Rewriting Config
// ============================================================================

struct RlsRule {
    std::string name;
    std::optional<std::string> database;
    std::optional<std::string> table;
    std::string condition;                  // SQL with $USER, $ROLES, $ATTR.key
    std::vector<std::string> users;
    std::vector<std::string> roles;
};

struct RewriteRule {
    std::string name;
    std::string type;                       // "enforce_limit"
    int limit_value = 1000;
    std::vector<std::string> users;
    std::vector<std::string> roles;
};

} // namespace sqlproxy
