#pragma once

#include "policy/policy_engine.hpp"
#include "core/types.hpp"
#include "core/utils.hpp"
#include <string>
#include <vector>
#include <optional>
#include <chrono>

namespace sqlproxy {

struct SimulationQuery {
    std::string user;
    std::vector<std::string> roles;
    std::string database;
    std::string sql;
    StatementType statement_type;
    std::vector<TableRef> source_tables;
    Decision original_decision;
    std::string original_policy;
};

struct SimulationDiff {
    std::string user;
    std::string sql;
    std::string database;
    Decision original_decision;
    Decision new_decision;
    std::string original_policy;
    std::string new_policy;
};

struct SimulationResult {
    size_t total_queries = 0;
    size_t changed = 0;
    size_t newly_blocked = 0;
    size_t newly_allowed = 0;
    size_t unchanged = 0;
    std::vector<SimulationDiff> diffs;
    std::chrono::microseconds duration{0};
};

class PolicySimulator {
public:
    /**
     * @brief Simulate proposed policies against historical queries.
     */
    [[nodiscard]] static SimulationResult simulate(
        const std::vector<Policy>& proposed_policies,
        const std::vector<SimulationQuery>& queries,
        size_t max_diffs = 100);

    /**
     * @brief Parse audit JSONL file into SimulationQuery vector.
     */
    [[nodiscard]] static std::vector<SimulationQuery> parse_audit_file(
        const std::string& audit_file_path,
        size_t limit = 0);

    /**
     * @brief Parse a single audit JSON line into a SimulationQuery.
     */
    [[nodiscard]] static std::optional<SimulationQuery> parse_audit_line(
        const std::string& json_line);

    /**
     * @brief Parse policies from JSON body (for simulation endpoint).
     */
    [[nodiscard]] static std::vector<Policy> parse_policies_json(const std::string& json);
};

} // namespace sqlproxy
