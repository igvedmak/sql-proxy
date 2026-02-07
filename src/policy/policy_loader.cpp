#include "policy/policy_loader.hpp"
#include "config/config_loader.hpp"
#include "core/utils.hpp"

#include <format>
#include <fstream>

namespace sqlproxy {

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
        if (!config.contains("policies") || !config["policies"].is_array()) {
            return LoadResult::error("No [[policies]] array found in configuration");
        }

        const auto& policies_array = config["policies"];

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
                    "Policy '" + policy.name + "': Invalid action '" + action_str + "'");
            }
            policy.action = *action;

            // Optional: users array
            if (node.contains("users") && node["users"].is_array()) {
                for (const auto& user : node["users"]) {
                    if (user.is_string()) {
                        const std::string user_str = user.get<std::string>();
                        if (!user_str.empty()) {
                            policy.users.insert(user_str);
                        }
                    }
                }
            }

            // Optional: roles array
            if (node.contains("roles") && node["roles"].is_array()) {
                for (const auto& role : node["roles"]) {
                    if (role.is_string()) {
                        const std::string role_str = role.get<std::string>();
                        if (!role_str.empty()) {
                            policy.roles.insert(role_str);
                        }
                    }
                }
            }

            // Optional: exclude_roles array
            if (node.contains("exclude_roles") && node["exclude_roles"].is_array()) {
                for (const auto& role : node["exclude_roles"]) {
                    if (role.is_string()) {
                        const std::string role_str = role.get<std::string>();
                        if (!role_str.empty()) {
                            policy.exclude_roles.insert(role_str);
                        }
                    }
                }
            }

            // Optional: statement_types array
            if (node.contains("statement_types") && node["statement_types"].is_array()) {
                for (const auto& stmt : node["statement_types"]) {
                    if (stmt.is_string()) {
                        const std::string stmt_str = stmt.get<std::string>();
                        const auto stmt_type = parse_statement_type(stmt_str);
                        if (stmt_type) {
                            policy.scope.operations.insert(*stmt_type);
                        } else if (!stmt_str.empty()) {
                            return LoadResult::error(
                                "Policy '" + policy.name +
                                "': Invalid statement type '" + stmt_str + "'");
                        }
                    }
                }
            }

            // Optional: Scope fields (database, schema, table)
            if (node.contains("database") && node["database"].is_string()) {
                policy.scope.database = node["database"].get<std::string>();
            }
            if (node.contains("schema") && node["schema"].is_string()) {
                policy.scope.schema = node["schema"].get<std::string>();
            }
            if (node.contains("table") && node["table"].is_string()) {
                policy.scope.table = node["table"].get<std::string>();
            }

            // Optional: reason (for audit logs)
            policy.reason = node.value("reason", std::string(""));

            // Validate policy
            std::string error_msg;
            if (!validate_policy(policy, error_msg)) {
                return LoadResult::error("Policy '" + policy.name + "': " + error_msg);
            }

            policies.push_back(std::move(policy));
        }

        return LoadResult::ok(std::move(policies));

    } catch (const std::exception& e) {
        return LoadResult::error(std::string("Error parsing policies: ") + e.what());
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
