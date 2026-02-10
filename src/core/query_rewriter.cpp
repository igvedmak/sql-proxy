#include "core/query_rewriter.hpp"
#include "core/utils.hpp"

#include <algorithm>
#include <format>

namespace sqlproxy {

void QueryRewriter::load_rules(
    const std::vector<RlsRule>& rls_rules,
    const std::vector<RewriteRule>& rewrite_rules) {

    auto store = std::make_shared<RuleStore>();
    store->rls_rules = rls_rules;
    store->rewrite_rules = rewrite_rules;

    std::unique_lock lock(mutex_);
    store_ = std::move(store);
}

void QueryRewriter::reload_rules(
    const std::vector<RlsRule>& rls_rules,
    const std::vector<RewriteRule>& rewrite_rules) {
    load_rules(rls_rules, rewrite_rules);
}

std::string QueryRewriter::rewrite(
    const std::string& sql,
    const std::string& user,
    const std::vector<std::string>& roles,
    const std::string& database,
    const AnalysisResult& analysis,
    const std::unordered_map<std::string, std::string>& user_attributes) const {

    std::shared_ptr<RuleStore> store;
    {
        std::shared_lock lock(mutex_);
        store = store_;
    }

    if (!store) return {};

    std::string result = sql;
    bool modified = false;

    // 1. Apply RLS rules (inject WHERE clauses)
    if (analysis.statement_type == StatementType::SELECT) {
        for (const auto& rule : store->rls_rules) {
            // Check database match
            if (rule.database && *rule.database != database) continue;

            // Check user/role match
            if (!matches_user_or_role(rule.users, rule.roles, user, roles)) continue;

            // Check table match
            if (rule.table) {
                bool table_found = false;
                for (const auto& t : analysis.source_tables) {
                    if (t.table == *rule.table) {
                        table_found = true;
                        break;
                    }
                }
                if (!table_found) continue;
            }

            // Expand template and inject WHERE
            std::string condition = expand_template(rule.condition, user, roles, user_attributes);
            std::string rewritten = inject_where(result, condition);
            if (!rewritten.empty()) {
                result = std::move(rewritten);
                modified = true;
            }
        }
    }

    // 2. Apply enforce_limit rules
    if (analysis.statement_type == StatementType::SELECT) {
        for (const auto& rule : store->rewrite_rules) {
            if (rule.type != "enforce_limit") continue;
            if (!matches_user_or_role(rule.users, rule.roles, user, roles)) continue;

            std::string rewritten = enforce_limit(result, rule.limit_value);
            if (!rewritten.empty()) {
                result = std::move(rewritten);
                modified = true;
            }
        }
    }

    return modified ? result : std::string{};
}

std::string QueryRewriter::expand_template(
    const std::string& condition,
    const std::string& user,
    const std::vector<std::string>& roles,
    const std::unordered_map<std::string, std::string>& attributes) {

    std::string result = condition;

    // Replace $USER
    {
        const std::string placeholder = "$USER";
        size_t pos = 0;
        while ((pos = result.find(placeholder, pos)) != std::string::npos) {
            result.replace(pos, placeholder.size(), user);
            pos += user.size();
        }
    }

    // Replace $ROLES (comma-separated quoted)
    {
        const std::string placeholder = "$ROLES";
        size_t pos = result.find(placeholder);
        if (pos != std::string::npos) {
            std::string roles_str;
            for (size_t i = 0; i < roles.size(); ++i) {
                if (i > 0) roles_str += ",";
                roles_str += "'";
                roles_str += roles[i];
                roles_str += "'";
            }
            result.replace(pos, placeholder.size(), roles_str);
        }
    }

    // Replace $ATTR.key
    {
        const std::string prefix = "$ATTR.";
        size_t pos = 0;
        while ((pos = result.find(prefix, pos)) != std::string::npos) {
            // Find end of attribute key (alphanumeric + underscore)
            const size_t key_start = pos + prefix.size();
            size_t key_end = key_start;
            while (key_end < result.size() &&
                   (std::isalnum(result[key_end]) || result[key_end] == '_')) {
                ++key_end;
            }

            std::string key = result.substr(key_start, key_end - key_start);
            auto it = attributes.find(key);
            const std::string& value = (it != attributes.end()) ? it->second : key;

            result.replace(pos, key_end - pos, value);
            pos += value.size();
        }
    }

    return result;
}

std::string QueryRewriter::inject_where(
    const std::string& sql, const std::string& condition) {

    if (condition.empty()) return {};

    // Find WHERE clause (case-insensitive)
    std::string lower = utils::to_lower(sql);

    const size_t where_pos = lower.find(" where ");
    if (where_pos != std::string::npos) {
        // WHERE exists → append AND (condition) after WHERE
        const size_t insert_pos = where_pos + 7; // after " where "

        std::string result = sql.substr(0, insert_pos);
        result += "(";
        result += condition;
        result += ") AND ";
        result += sql.substr(insert_pos);
        return result;
    }

    // No WHERE → find insertion point (before ORDER BY, GROUP BY, HAVING, LIMIT, or end)
    static const std::vector<std::string> terminators = {
        " order by ", " group by ", " having ", " limit ", " union ", " intersect ", " except "
    };

    size_t insert_pos = sql.size();
    for (const auto& term : terminators) {
        const size_t pos = lower.find(term);
        if (pos != std::string::npos && pos < insert_pos) {
            insert_pos = pos;
        }
    }

    // Also check for trailing semicolon
    const size_t semi = sql.rfind(';');
    if (semi != std::string::npos && semi < insert_pos) {
        insert_pos = semi;
    }

    std::string result = sql.substr(0, insert_pos);
    result += " WHERE (";
    result += condition;
    result += ")";
    if (insert_pos < sql.size()) {
        result += sql.substr(insert_pos);
    }
    return result;
}

std::string QueryRewriter::enforce_limit(
    const std::string& sql, int limit_value) {

    // Check if LIMIT already exists (case-insensitive)
    const std::string lower = utils::to_lower(sql);
    if (lower.contains(" limit ")) {
        return {};  // Already has LIMIT
    }

    // Find insertion point (before trailing semicolon or end)
    size_t insert_pos = sql.size();
    const size_t semi = sql.rfind(';');
    if (semi != std::string::npos) {
        insert_pos = semi;
    }

    std::string result = sql.substr(0, insert_pos);
    result += std::format(" LIMIT {}", limit_value);
    if (insert_pos < sql.size()) {
        result += sql.substr(insert_pos);
    }
    return result;
}

bool QueryRewriter::matches_user_or_role(
    const std::vector<std::string>& rule_users,
    const std::vector<std::string>& rule_roles,
    const std::string& user,
    const std::vector<std::string>& user_roles) {

    // If no users and no roles specified → matches all
    if (rule_users.empty() && rule_roles.empty()) return true;

    // Check user match
    for (const auto& u : rule_users) {
        if (u == user || u == "*") return true;
    }

    // Check role match
    for (const auto& rr : rule_roles) {
        for (const auto& ur : user_roles) {
            if (rr == ur) return true;
        }
    }

    return false;
}

} // namespace sqlproxy
