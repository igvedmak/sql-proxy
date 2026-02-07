#include "policy/policy_loader.hpp"
#include "config/config_loader.hpp"
#include "core/utils.hpp"

#include <fstream>
#include <sstream>

namespace sqlproxy {

// ============================================================================
// Public API - Load from file
// ============================================================================

PolicyLoader::LoadResult PolicyLoader::load_from_file(const std::string& config_path) {
    // Read file contents
    std::ifstream file(config_path);
    if (!file.is_open()) {
        return LoadResult::error("Cannot open config file: " + config_path);
    }

    std::ostringstream buffer;
    buffer << file.rdbuf();
    return load_from_string(buffer.str());
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
    std::string lower = utils::to_lower(type_str);

    if (lower == "select") return StatementType::SELECT;
    if (lower == "insert") return StatementType::INSERT;
    if (lower == "update") return StatementType::UPDATE;
    if (lower == "delete") return StatementType::DELETE;
    if (lower == "create_table") return StatementType::CREATE_TABLE;
    if (lower == "alter_table") return StatementType::ALTER_TABLE;
    if (lower == "drop_table") return StatementType::DROP_TABLE;
    if (lower == "create_index") return StatementType::CREATE_INDEX;
    if (lower == "drop_index") return StatementType::DROP_INDEX;
    if (lower == "truncate") return StatementType::TRUNCATE;
    if (lower == "begin") return StatementType::BEGIN;
    if (lower == "commit") return StatementType::COMMIT;
    if (lower == "rollback") return StatementType::ROLLBACK;

    return std::nullopt;
}

std::optional<Decision> PolicyLoader::parse_action(const std::string& action_str) {
    std::string lower = utils::to_lower(action_str);

    if (lower == "allow") return Decision::ALLOW;
    if (lower == "block") return Decision::BLOCK;

    return std::nullopt;
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
