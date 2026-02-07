#pragma once

#include "core/types.hpp"
#include <string>
#include <vector>
#include <system_error>

namespace sqlproxy {

/**
 * @brief Policy loader from TOML configuration
 *
 * Loads and validates policies from proxy.toml config file.
 * Validates:
 * - Priority values
 * - Action values (ALLOW/BLOCK)
 * - Statement types
 * - Scope constraints
 */
class PolicyLoader {
public:
    /**
     * @brief Load result
     */
    struct LoadResult {
        bool success;
        std::string error_message;
        std::vector<Policy> policies;

        static LoadResult ok(std::vector<Policy> policies_vec) {
            LoadResult result;
            result.success = true;
            result.policies = std::move(policies_vec);
            return result;
        }

        static LoadResult error(std::string message) {
            LoadResult result;
            result.success = false;
            result.error_message = std::move(message);
            return result;
        }
    };

    /**
     * @brief Load policies from TOML file
     * @param config_path Path to proxy.toml
     * @return Load result with policies or error
     */
    static LoadResult load_from_file(const std::string& config_path);

    /**
     * @brief Load policies from TOML string
     * @param toml_content TOML content
     * @return Load result with policies or error
     */
    static LoadResult load_from_string(const std::string& toml_content);

private:
    /**
     * @brief Parse statement type from string
     */
    static std::optional<StatementType> parse_statement_type(const std::string& type_str);

    /**
     * @brief Parse action from string
     */
    static std::optional<Decision> parse_action(const std::string& action_str);

    /**
     * @brief Validate policy
     */
    static bool validate_policy(const Policy& policy, std::string& error_msg);
};

} // namespace sqlproxy
