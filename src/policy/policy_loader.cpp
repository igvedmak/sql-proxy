#include "policy/policy_loader.hpp"
#include "core/utils.hpp"

#include <toml.hpp>
#include <format>
#include <fstream>

using namespace std::string_literals;

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
// Helper: extract string set from a toml array
// ============================================================================

namespace {

void extract_string_set(const toml::table& tbl, std::string_view key,
                        std::unordered_set<std::string>& out) {
    const auto* arr = tbl[key].as_array();
    if (!arr) return;
    for (const auto& elem : *arr) {
        if (const auto* s = elem.as_string(); s && !s->get().empty()) {
            out.insert(std::string(s->get()));
        }
    }
}

} // anonymous namespace

// ============================================================================
// Public API - Load from file
// ============================================================================

PolicyLoader::LoadResult PolicyLoader::load_from_file(const std::string& config_path) {
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
        auto config = toml::parse(toml_content);

        // Extract [[policies]] array
        const auto* policies_array = config[kPolicies].as_array();
        if (!policies_array) {
            return LoadResult::error("No [[policies]] array found in configuration");
        }

        // Parse each policy
        for (const auto& elem : *policies_array) {
            const auto* node = elem.as_table();
            if (!node) continue;
            const auto& tbl = *node;

            Policy policy;

            // Required: name
            policy.name = tbl["name"].value_or(""s);
            if (policy.name.empty()) {
                return LoadResult::error("Policy must have a name");
            }

            // Required: priority
            policy.priority = tbl["priority"].value_or(0);

            // Required: action (ALLOW or BLOCK)
            const std::string action_str = tbl["action"].value_or("BLOCK"s);
            const auto action = parse_action(action_str);
            if (!action) {
                return LoadResult::error(
                    std::format("Policy '{}': Invalid action '{}'", policy.name, action_str));
            }
            policy.action = *action;

            // Optional: users array
            extract_string_set(tbl, kUsers, policy.users);

            // Optional: roles array
            extract_string_set(tbl, kRoles, policy.roles);

            // Optional: exclude_roles array
            extract_string_set(tbl, kExcludeRoles, policy.exclude_roles);

            // Optional: statement_types array
            if (const auto* stmt_arr = tbl[kStatementTypes].as_array()) {
                for (const auto& stmt : *stmt_arr) {
                    if (const auto* s = stmt.as_string()) {
                        const std::string stmt_str(s->get());
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
            if (auto v = tbl[kDatabase].value<std::string>()) policy.scope.database = *v;
            if (auto v = tbl[kSchema].value<std::string>())   policy.scope.schema = *v;
            if (auto v = tbl[kTable].value<std::string>())     policy.scope.table = *v;

            // Optional: columns array (column-level ACL)
            if (const auto* col_arr = tbl["columns"].as_array()) {
                for (const auto& col : *col_arr) {
                    if (const auto* s = col.as_string(); s && !s->get().empty()) {
                        policy.scope.columns.emplace_back(std::string(s->get()));
                    }
                }
            }

            // Optional: masking fields (for column-level ALLOW policies)
            if (auto masking_str_opt = tbl["masking_action"].value<std::string>()) {
                static const std::unordered_map<std::string, MaskingAction> masking_lookup = {
                    {"none", MaskingAction::NONE},
                    {"redact", MaskingAction::REDACT},
                    {"partial", MaskingAction::PARTIAL},
                    {"hash", MaskingAction::HASH},
                    {"nullify", MaskingAction::NULLIFY},
                };
                const std::string masking_str = utils::to_lower(*masking_str_opt);
                const auto mit = masking_lookup.find(masking_str);
                if (mit != masking_lookup.end()) {
                    policy.masking_action = mit->second;
                }
            }
            policy.masking_prefix_len = tbl["masking_prefix_len"].value_or(3);
            policy.masking_suffix_len = tbl["masking_suffix_len"].value_or(3);

            // Optional: reason (for audit logs)
            policy.reason = tbl["reason"].value_or(""s);

            // Optional: shadow mode (log-only, don't enforce)
            policy.shadow = tbl["shadow"].value_or(false);

            // Validate policy
            std::string error_msg;
            if (!validate_policy(policy, error_msg)) {
                return LoadResult::error(std::format("Policy '{}': {}", policy.name, error_msg));
            }

            policies.emplace_back(std::move(policy));
        }

        return LoadResult::ok(std::move(policies));

    } catch (const toml::parse_error& e) {
        return LoadResult::error(std::format("TOML parse error: {}", e.what()));
    } catch (const std::exception& e) {
        return LoadResult::error(std::format("Error parsing policies: {}", e.what()));
    }
}

// ============================================================================
// Private Helpers
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
    if (policy.name.empty()) {
        error_msg = "Policy must have a name";
        return false;
    }

    if (policy.action != Decision::ALLOW && policy.action != Decision::BLOCK) {
        error_msg = "Policy action must be ALLOW or BLOCK";
        return false;
    }

    if (policy.priority < 0) {
        error_msg = "Policy priority must be non-negative";
        return false;
    }

    if (policy.users.empty() && policy.roles.empty()) {
        error_msg = "Policy must specify at least one user or role";
        return false;
    }

    return true;
}

} // namespace sqlproxy
