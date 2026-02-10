#include "policy/policy_loader.hpp"
#include "config/config_loader.hpp"
#include "core/utils.hpp"

#include <format>
#include <fstream>

namespace sqlproxy {

// Constexpr config keys (used 2+ times in policy parsing)
static constexpr std::string_view kPolicies       = "policies";
static constexpr std::string_view kUsers          = "users";
static constexpr std::string_view kRoles          = "roles";
static constexpr std::string_view kExcludeRoles   = "exclude_roles";
static constexpr std::string_view kStatementTypes = "statement_types";
static constexpr std::string_view kDatabase       = "database";
static constexpr std::string_view kSchema         = "schema";
static constexpr std::string_view kTable          = "table";

// ============================================================================
// Public API - Load from file
// ============================================================================

PolicyLoader::LoadResult PolicyLoader::load_from_file(const std::string& config_path) {
    // Read file contents
    std::ifstream file(config_path);
    if (!file.is_open()) {
        return LoadResult::error(std::format("Cannot open config file: {}", config_path));
    }

    std::string buffer((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());
    return load_from_string(buffer);
}

// ============================================================================
// Public API - Load from string
// ============================================================================

PolicyLoader::LoadResult PolicyLoader::load_from_string(const std::string& toml_content) {
    std::vector<Policy> policies;

    try {
        // Parse TOML into JSON using our lightweight parser
        const auto config = toml::parse_string(toml_content);

        // Extract [[policies]] array
        if (!config.contains(kPolicies) || !config[kPolicies].is_array()) {
            return LoadResult::error("No [[policies]] array found in configuration");
        }

        const auto& policies_array = config[kPolicies];

        // Parse each policy
        for (const auto& node : policies_array) {
            Policy policy;

            // Required: name
            policy.name = node.value("name", std::string(""));
            if (policy.name.empty()) {
                return LoadResult::error("Policy must have a name");
            }

            // Required: priority
            policy.priority = node.value("priority", 0);

            // Required: action (ALLOW or BLOCK)
            const std::string action_str = node.value("action", std::string("BLOCK"));
            const auto action = parse_action(action_str);
            if (!action) {
                return LoadResult::error(
                    std::format("Policy '{}': Invalid action '{}'", policy.name, action_str));
            }
            policy.action = *action;

            // Optional: users array
            if (node.contains(kUsers) && node[kUsers].is_array()) {
                for (const auto& user : node[kUsers]) {
                    if (user.is_string()) {
                        const std::string user_str = user.get<std::string>();
                        if (!user_str.empty()) {
                            policy.users.insert(user_str);
                        }
                    }
                }
            }

            // Optional: roles array
            if (node.contains(kRoles) && node[kRoles].is_array()) {
                for (const auto& role : node[kRoles]) {
                    if (role.is_string()) {
                        const std::string role_str = role.get<std::string>();
                        if (!role_str.empty()) {
                            policy.roles.insert(role_str);
                        }
                    }
                }
            }

            // Optional: exclude_roles array
            if (node.contains(kExcludeRoles) && node[kExcludeRoles].is_array()) {
                for (const auto& role : node[kExcludeRoles]) {
                    if (role.is_string()) {
                        const std::string role_str = role.get<std::string>();
                        if (!role_str.empty()) {
                            policy.exclude_roles.insert(role_str);
                        }
                    }
                }
            }

            // Optional: statement_types array
            if (node.contains(kStatementTypes) && node[kStatementTypes].is_array()) {
                for (const auto& stmt : node[kStatementTypes]) {
                    if (stmt.is_string()) {
                        const std::string stmt_str = stmt.get<std::string>();
                        const auto stmt_type = parse_statement_type(stmt_str);
                        if (stmt_type) {
                            policy.scope.operations.insert(*stmt_type);
                        } else if (!stmt_str.empty()) {
                            return LoadResult::error(
                                std::format("Policy '{}': Invalid statement type '{}'", policy.name, stmt_str));
                        }
                    }
                }
            }

            // Optional: Scope fields (database, schema, table)
            if (node.contains(kDatabase) && node[kDatabase].is_string()) {
                policy.scope.database = node[kDatabase].get<std::string>();
            }
            if (node.contains(kSchema) && node[kSchema].is_string()) {
                policy.scope.schema = node[kSchema].get<std::string>();
            }
            if (node.contains(kTable) && node[kTable].is_string()) {
                policy.scope.table = node[kTable].get<std::string>();
            }

            // Optional: columns array (column-level ACL)
            if (node.contains("columns") && node["columns"].is_array()) {
                for (const auto& col : node["columns"]) {
                    if (col.is_string()) {
                        std::string col_str = col.get<std::string>();
                        if (!col_str.empty()) {
                            policy.scope.columns.emplace_back(std::move(col_str));
                        }
                    }
                }
            }

            // Optional: masking fields (for column-level ALLOW policies)
            if (node.contains("masking_action") && node["masking_action"].is_string()) {
                static const std::unordered_map<std::string, MaskingAction> masking_lookup = {
                    {"none", MaskingAction::NONE},
                    {"redact", MaskingAction::REDACT},
                    {"partial", MaskingAction::PARTIAL},
                    {"hash", MaskingAction::HASH},
                    {"nullify", MaskingAction::NULLIFY},
                };
                const std::string masking_str = utils::to_lower(node["masking_action"].get<std::string>());
                const auto mit = masking_lookup.find(masking_str);
                if (mit != masking_lookup.end()) {
                    policy.masking_action = mit->second;
                }
            }
            policy.masking_prefix_len = node.value("masking_prefix_len", 3);
            policy.masking_suffix_len = node.value("masking_suffix_len", 3);

            // Optional: reason (for audit logs)
            policy.reason = node.value("reason", std::string(""));

            // Optional: shadow mode (log-only, don't enforce)
            if (node.contains("shadow") && node["shadow"].is_boolean()) {
                policy.shadow = node["shadow"].get<bool>();
            }

            // Validate policy
            std::string error_msg;
            if (!validate_policy(policy, error_msg)) {
                return LoadResult::error(std::format("Policy '{}': {}", policy.name, error_msg));
            }

            policies.emplace_back(std::move(policy));
        }

        return LoadResult::ok(std::move(policies));

    } catch (const std::exception& e) {
        return LoadResult::error(std::format("Error parsing policies: {}", e.what()));
    }
}

// ============================================================================
// Private Helpers - kept as-is from original implementation
// ============================================================================

std::optional<StatementType> PolicyLoader::parse_statement_type(const std::string& type_str) {
    const std::string lower = utils::to_lower(type_str);

    static const std::unordered_map<std::string, StatementType> lookup = {
        {"select",       StatementType::SELECT},
        {"insert",       StatementType::INSERT},
        {"update",       StatementType::UPDATE},
        {"delete",       StatementType::DELETE},
        {"create_table", StatementType::CREATE_TABLE},
        {"alter_table",  StatementType::ALTER_TABLE},
        {"drop_table",   StatementType::DROP_TABLE},
        {"create_index", StatementType::CREATE_INDEX},
        {"drop_index",   StatementType::DROP_INDEX},
        {"truncate",     StatementType::TRUNCATE},
        {"begin",        StatementType::BEGIN},
        {"commit",       StatementType::COMMIT},
        {"rollback",     StatementType::ROLLBACK},
    };

    const auto it = lookup.find(lower);
    return (it != lookup.end()) ? std::make_optional(it->second) : std::nullopt;
}

std::optional<Decision> PolicyLoader::parse_action(const std::string& action_str) {
    const std::string lower = utils::to_lower(action_str);
    
    static const std::unordered_map<std::string, Decision> lookup = {
        {"allow", Decision::ALLOW},
        {"block", Decision::BLOCK},
    };

    const auto it = lookup.find(lower);
    return (it != lookup.end()) ? std::make_optional(it->second) : std::nullopt;
}

bool PolicyLoader::validate_policy(const Policy& policy, std::string& error_msg) {
    // Validate policy has a name
    if (policy.name.empty()) {
        error_msg = "Policy must have a name";
        return false;
    }

    // Validate action
    if (policy.action != Decision::ALLOW && policy.action != Decision::BLOCK) {
        error_msg = "Policy action must be ALLOW or BLOCK";
        return false;
    }

    // Validate priority
    if (policy.priority < 0) {
        error_msg = "Policy priority must be non-negative";
        return false;
    }

    // Validate at least one user or role
    if (policy.users.empty() && policy.roles.empty()) {
        error_msg = "Policy must specify at least one user or role";
        return false;
    }

    return true;
}

} // namespace sqlproxy
