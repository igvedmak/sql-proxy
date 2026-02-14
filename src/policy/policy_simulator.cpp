#include "policy/policy_simulator.hpp"
#include "core/utils.hpp"

#include <fstream>
#include <algorithm>

namespace sqlproxy {

// ============================================================================
// Simulation
// ============================================================================

SimulationResult PolicySimulator::simulate(
    const std::vector<Policy>& proposed_policies,
    const std::vector<SimulationQuery>& queries,
    size_t max_diffs) {

    utils::Timer timer;

    PolicyEngine engine;
    engine.load_policies(proposed_policies);

    SimulationResult result;
    result.total_queries = queries.size();

    for (const auto& q : queries) {
        // Reconstruct minimal AnalysisResult
        AnalysisResult analysis;
        analysis.statement_type = q.statement_type;
        analysis.source_tables = q.source_tables;

        const auto eval = engine.evaluate(q.user, q.roles, q.database, analysis);

        if (eval.decision != q.original_decision) {
            ++result.changed;
            if (eval.decision == Decision::BLOCK) {
                ++result.newly_blocked;
            } else {
                ++result.newly_allowed;
            }
            if (result.diffs.size() < max_diffs) {
                result.diffs.push_back({
                    q.user, q.sql, q.database,
                    q.original_decision, eval.decision,
                    q.original_policy, eval.matched_policy
                });
            }
        } else {
            ++result.unchanged;
        }
    }

    result.duration = timer.elapsed_us();
    return result;
}

// ============================================================================
// Audit File Parsing
// ============================================================================

std::vector<SimulationQuery> PolicySimulator::parse_audit_file(
    const std::string& audit_file_path, size_t limit) {

    std::vector<SimulationQuery> queries;
    std::ifstream file(audit_file_path);
    if (!file.is_open()) return queries;

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        auto q = parse_audit_line(line);
        if (q) {
            queries.emplace_back(std::move(*q));
            if (limit > 0 && queries.size() >= limit) break;
        }
    }
    return queries;
}

// ============================================================================
// JSON field extraction helpers (lightweight, no JSON library)
// ============================================================================

namespace {

// Extract a quoted string value for a given key from JSON
std::string extract_string(const std::string& json, const std::string& key) {
    const auto key_str = "\"" + key + "\"";
    const auto pos = json.find(key_str);
    if (pos == std::string::npos) return "";

    const auto colon = json.find(':', pos + key_str.size());
    if (colon == std::string::npos) return "";

    // Skip whitespace
    auto val_start = colon + 1;
    while (val_start < json.size() && (json[val_start] == ' ' || json[val_start] == '\t'))
        ++val_start;

    if (val_start >= json.size() || json[val_start] != '"') return "";

    const auto val_end = utils::find_unescaped_quote(json, val_start + 1);
    if (val_end == std::string::npos) return "";

    return utils::unescape_json(json.substr(val_start + 1, val_end - val_start - 1));
}

// Extract a JSON array of strings
std::vector<std::string> extract_string_array(const std::string& json, const std::string& key) {
    std::vector<std::string> result;
    const auto key_str = "\"" + key + "\"";
    const auto pos = json.find(key_str);
    if (pos == std::string::npos) return result;

    const auto bracket = json.find('[', pos + key_str.size());
    if (bracket == std::string::npos) return result;

    const auto end_bracket = json.find(']', bracket);
    if (end_bracket == std::string::npos) return result;

    const auto segment = json.substr(bracket + 1, end_bracket - bracket - 1);

    // Parse quoted strings from segment
    size_t i = 0;
    while (i < segment.size()) {
        const auto qs = segment.find('"', i);
        if (qs == std::string::npos) break;
        const auto qe = utils::find_unescaped_quote(segment, qs + 1);
        if (qe == std::string::npos) break;
        result.push_back(segment.substr(qs + 1, qe - qs - 1));
        i = qe + 1;
    }
    return result;
}

} // anonymous namespace

std::optional<SimulationQuery> PolicySimulator::parse_audit_line(const std::string& json_line) {
    auto user = extract_string(json_line, "user");
    auto database = extract_string(json_line, "database");
    auto sql = extract_string(json_line, "sql");
    const auto stmt_type_str = extract_string(json_line, "statement_type");
    const auto decision_str = extract_string(json_line, "decision");
    auto matched_policy = extract_string(json_line, "matched_policy");
    const auto tables = extract_string_array(json_line, "tables");

    // Must have at minimum: user, sql, decision
    if (user.empty() || sql.empty() || decision_str.empty()) {
        return std::nullopt;
    }

    SimulationQuery q;
    q.user = std::move(user);
    q.database = database.empty() ? "default" : std::move(database);
    q.sql = std::move(sql);
    q.statement_type = statement_type_from_string(stmt_type_str);
    q.original_decision = decision_from_string(decision_str);
    q.original_policy = std::move(matched_policy);

    // Convert table names to TableRef
    for (const auto& t : tables) {
        q.source_tables.emplace_back(t);
    }

    return q;
}

// ============================================================================
// Policy JSON Parsing (for simulation endpoint)
// ============================================================================

std::vector<Policy> PolicySimulator::parse_policies_json(const std::string& json) {
    std::vector<Policy> policies;

    // Find "policies" array
    const auto arr_pos = json.find("\"policies\"");
    if (arr_pos == std::string::npos) return policies;

    const auto bracket = json.find('[', arr_pos);
    if (bracket == std::string::npos) return policies;

    // Find matching close bracket
    int depth = 1;
    size_t end_bracket = bracket + 1;
    while (end_bracket < json.size() && depth > 0) {
        if (json[end_bracket] == '[') ++depth;
        else if (json[end_bracket] == ']') --depth;
        if (depth > 0) ++end_bracket;
    }
    if (depth != 0) return policies;

    // Parse individual policy objects within the array
    size_t pos = bracket + 1;
    while (pos < end_bracket) {
        const auto obj_start = json.find('{', pos);
        if (obj_start == std::string::npos || obj_start >= end_bracket) break;

        // Find matching close brace
        int brace_depth = 1;
        size_t obj_end = obj_start + 1;
        while (obj_end < json.size() && brace_depth > 0) {
            if (json[obj_end] == '{') ++brace_depth;
            else if (json[obj_end] == '}') --brace_depth;
            if (brace_depth > 0) ++obj_end;
        }
        if (brace_depth != 0) break;

        const auto obj = json.substr(obj_start, obj_end - obj_start + 1);

        Policy p;
        p.name = extract_string(obj, "name");
        if (p.name.empty()) p.name = "sim-policy-" + std::to_string(policies.size());

        const auto action_str = extract_string(obj, "action");
        p.action = decision_from_string(action_str);

        const auto table = extract_string(obj, "table");
        if (!table.empty()) p.scope.table = table;

        const auto schema = extract_string(obj, "schema");
        if (!schema.empty()) p.scope.schema = schema;

        const auto database = extract_string(obj, "database");
        if (!database.empty()) p.scope.database = database;

        auto users = extract_string_array(obj, "users");
        for (auto& u : users) p.users.insert(std::move(u));
        if (p.users.empty()) p.users.insert("*");

        auto roles = extract_string_array(obj, "roles");
        for (auto& r : roles) p.roles.insert(std::move(r));

        auto columns = extract_string_array(obj, "columns");
        p.scope.columns = std::move(columns);

        // Extract priority (numeric)
        const auto priority_pos = obj.find("\"priority\"");
        if (priority_pos != std::string::npos) {
            const auto colon = obj.find(':', priority_pos);
            if (colon != std::string::npos) {
                auto val_start = colon + 1;
                while (val_start < obj.size() && (obj[val_start] == ' ' || obj[val_start] == '\t'))
                    ++val_start;
                p.priority = static_cast<int>(std::strtol(obj.c_str() + val_start, nullptr, 10));
            }
        }

        policies.emplace_back(std::move(p));
        pos = obj_end + 1;
    }

    return policies;
}

} // namespace sqlproxy
