#include "config/config_loader.hpp"
#include "core/utils.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <algorithm>

namespace sqlproxy {

// ============================================================================
// TOML Parser Implementation
// ============================================================================

namespace toml {

namespace {

// ---- Parsing helpers -------------------------------------------------------

/**
 * @brief Strip inline comments from a line.
 *
 * A '#' is a comment start only when it is NOT inside a quoted string.
 * This handles both single-line keys and inline arrays.
 */
std::string strip_comment(const std::string& line) {
    bool in_string = false;
    bool escaped = false;
    for (size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (c == '\\') {
            escaped = true;
            continue;
        }
        if (c == '"') {
            in_string = !in_string;
            continue;
        }
        if (c == '#' && !in_string) {
            return line.substr(0, i);
        }
    }
    return line;
}

/**
 * @brief Parse a TOML value token into a JSON value.
 *
 * Supports: strings, integers, floats, booleans, inline arrays.
 */
nlohmann::json parse_value(const std::string& raw) {
    const std::string val = utils::trim(raw);
    if (val.empty()) {
        return nlohmann::json(nullptr);
    }

    // Boolean
    if (val == "true")  return nlohmann::json(true);
    if (val == "false") return nlohmann::json(false);

    // Quoted string
    if (val.size() >= 2 && val.front() == '"' && val.back() == '"') {
        // Unescape standard TOML escape sequences
        std::string result;
        result.reserve(val.size() - 2);
        for (size_t i = 1; i + 1 < val.size(); ++i) {
            if (val[i] == '\\' && i + 2 < val.size()) {
                const char next = val[i + 1];
                switch (next) {
                    case '"':  result += '"';  ++i; break;
                    case '\\': result += '\\'; ++i; break;
                    case 'n':  result += '\n'; ++i; break;
                    case 't':  result += '\t'; ++i; break;
                    case 'r':  result += '\r'; ++i; break;
                    default:   result += val[i]; break; // Keep backslash for unknown
                }
            } else {
                result += val[i];
            }
        }
        return nlohmann::json(result);
    }

    // Inline array  ["a", "b", ...]
    if (val.front() == '[' && val.back() == ']') {
        nlohmann::json arr = nlohmann::json::array();
        const std::string inner = val.substr(1, val.size() - 2);

        // Tokenize respecting quoted strings
        std::string token;
        bool in_str = false;
        bool esc = false;
        for (size_t i = 0; i < inner.size(); ++i) {
            const char c = inner[i];
            if (esc) {
                token += c;
                esc = false;
                continue;
            }
            if (c == '\\') {
                token += c;
                esc = true;
                continue;
            }
            if (c == '"') {
                token += c;
                in_str = !in_str;
                continue;
            }
            if (c == ',' && !in_str) {
                const std::string trimmed = utils::trim(token);
                if (!trimmed.empty()) {
                    arr.push_back(parse_value(trimmed));
                }
                token.clear();
                continue;
            }
            token += c;
        }
        const std::string trimmed = utils::trim(token);
        if (!trimmed.empty()) {
            arr.push_back(parse_value(trimmed));
        }
        return arr;
    }

    // Integer or float
    // Try integer first (no decimal point)
    if (val.find('.') == std::string::npos) {
        try {
            const long long int_val = std::stoll(val);
            return nlohmann::json(int_val);
        } catch (...) {
            // Fall through
        }
    }

    // Float
    try {
        const double float_val = std::stod(val);
        return nlohmann::json(float_val);
    } catch (...) {
        // Fall through
    }

    // Treat as bare string (shouldn't happen in valid TOML, but be lenient)
    return nlohmann::json(val);
}

/**
 * @brief Parse a dotted key like "rate_limiting.global" into path segments.
 */
std::vector<std::string> parse_dotted_key(const std::string& key) {
    std::vector<std::string> parts;
    std::istringstream iss(key);
    std::string part;
    while (std::getline(iss, part, '.')) {
        const std::string trimmed = utils::trim(part);
        if (!trimmed.empty()) {
            parts.push_back(trimmed);
        }
    }
    return parts;
}

/**
 * @brief Navigate to (or create) a nested JSON object given a path.
 *
 * For a path like ["rate_limiting", "global"], returns a reference to
 * root["rate_limiting"]["global"], creating intermediate objects as needed.
 */
nlohmann::json& navigate_to(nlohmann::json& root, const std::vector<std::string>& path) {
    nlohmann::json* current = &root;
    for (const auto& segment : path) {
        if (!current->contains(segment)) {
            (*current)[segment] = nlohmann::json::object();
        }
        current = &(*current)[segment];
    }
    return *current;
}

} // anonymous namespace

nlohmann::json parse_string(const std::string& content) {
    nlohmann::json root = nlohmann::json::object();

    std::istringstream stream(content);
    std::string line;
    int line_num = 0;

    // Current section path, e.g., ["server"] or ["rate_limiting", "global"]
    std::vector<std::string> current_section;

    // For [[array]] sections, track the path and whether we're in an array section
    bool in_array_section = false;
    std::vector<std::string> array_section_path;

    // Multi-line array state
    bool in_multiline_array = false;
    std::string multiline_key;
    std::string multiline_buffer;
    nlohmann::json* multiline_target = nullptr;

    while (std::getline(stream, line)) {
        ++line_num;

        // Strip comment (respecting quotes)
        line = strip_comment(line);

        // Trim whitespace
        const std::string trimmed = utils::trim(line);

        // Skip empty lines
        if (trimmed.empty()) {
            continue;
        }

        // Handle multi-line array continuation
        if (in_multiline_array) {
            multiline_buffer += ' ';
            multiline_buffer += trimmed;

            // Check if the array is closed
            // Count unquoted brackets to handle nested structures
            int bracket_depth = 0;
            bool in_str = false;
            bool esc = false;
            for (char c : multiline_buffer) {
                if (esc) { esc = false; continue; }
                if (c == '\\') { esc = true; continue; }
                if (c == '"') { in_str = !in_str; continue; }
                if (!in_str) {
                    if (c == '[') ++bracket_depth;
                    if (c == ']') --bracket_depth;
                }
            }

            if (bracket_depth <= 0) {
                // Array is complete
                nlohmann::json value = parse_value(utils::trim(multiline_buffer));
                if (multiline_target) {
                    (*multiline_target)[multiline_key] = std::move(value);
                }
                in_multiline_array = false;
                multiline_buffer.clear();
                multiline_key.clear();
                multiline_target = nullptr;
            }
            continue;
        }

        // ---- [[array]] section header ----
        if (trimmed.size() >= 4 && trimmed.front() == '[' && trimmed[1] == '[') {
            // Find closing ]]
            const size_t close = trimmed.rfind("]]");
            if (close == std::string::npos) {
                throw std::runtime_error(
                    "TOML parse error at line " + std::to_string(line_num) +
                    ": unclosed [[array]] header");
            }
            const std::string section_name = utils::trim(
                trimmed.substr(2, close - 2));

            array_section_path = parse_dotted_key(section_name);
            in_array_section = true;

            // Ensure the array exists in the JSON tree
            // Navigate to parent, then ensure the last key is an array
            nlohmann::json* parent = &root;
            for (size_t i = 0; i + 1 < array_section_path.size(); ++i) {
                const auto& seg = array_section_path[i];
                if (!parent->contains(seg)) {
                    (*parent)[seg] = nlohmann::json::object();
                }
                parent = &(*parent)[seg];
            }

            const auto& array_key = array_section_path.back();
            if (!parent->contains(array_key)) {
                (*parent)[array_key] = nlohmann::json::array();
            }

            // Append a new empty object to the array
            (*parent)[array_key].push_back(nlohmann::json::object());

            // Current section points into this new array element
            // We'll track it via array_section_path
            current_section = array_section_path;
            continue;
        }

        // ---- [section] header ----
        if (trimmed.front() == '[' && trimmed.back() == ']') {
            const std::string section_name = utils::trim(
                trimmed.substr(1, trimmed.size() - 2));

            current_section = parse_dotted_key(section_name);
            in_array_section = false;

            // Ensure the section object exists
            navigate_to(root, current_section);
            continue;
        }

        // ---- key = value pair ----
        const size_t eq_pos = trimmed.find('=');
        if (eq_pos == std::string::npos) {
            // Not a key=value line; skip (tolerant parsing)
            continue;
        }

        const std::string key = utils::trim(trimmed.substr(0, eq_pos));
        const std::string value_str = utils::trim(trimmed.substr(eq_pos + 1));

        if (key.empty()) {
            continue;
        }

        // Determine target object
        nlohmann::json* target = nullptr;
        if (in_array_section) {
            // Navigate to the parent of the array, get the array, index last element
            nlohmann::json* parent = &root;
            for (size_t i = 0; i + 1 < array_section_path.size(); ++i) {
                parent = &(*parent)[array_section_path[i]];
            }
            auto& arr = (*parent)[array_section_path.back()];
            target = &arr.back();
        } else if (!current_section.empty()) {
            target = &navigate_to(root, current_section);
        } else {
            target = &root;
        }

        // Check for multi-line array: value starts with '[' but doesn't end with ']'
        if (!value_str.empty() && value_str.front() == '[') {
            // Count brackets
            int bracket_depth = 0;
            bool in_str = false;
            bool esc = false;
            for (char c : value_str) {
                if (esc) { esc = false; continue; }
                if (c == '\\') { esc = true; continue; }
                if (c == '"') { in_str = !in_str; continue; }
                if (!in_str) {
                    if (c == '[') ++bracket_depth;
                    if (c == ']') --bracket_depth;
                }
            }

            if (bracket_depth > 0) {
                // Multi-line array: accumulate until brackets balance
                in_multiline_array = true;
                multiline_key = key;
                multiline_buffer = value_str;
                multiline_target = target;
                continue;
            }
        }

        // Parse and assign value
        nlohmann::json value = parse_value(value_str);
        (*target)[key] = std::move(value);
    }

    if (in_multiline_array) {
        throw std::runtime_error(
            "TOML parse error: unterminated multi-line array for key '" +
            multiline_key + "'");
    }

    return root;
}

nlohmann::json parse_file(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        throw std::runtime_error(
            "Cannot open TOML file: " + file_path);
    }

    std::ostringstream buffer;
    buffer << file.rdbuf();
    return parse_string(buffer.str());
}

} // namespace toml

// ============================================================================
// ConfigLoader Implementation
// ============================================================================

// ---- Helpers ---------------------------------------------------------------

std::optional<StatementType> ConfigLoader::parse_statement_type(const std::string& type_str) {
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
        {"set",          StatementType::SET},
        {"show",         StatementType::SHOW},
    };

    const auto it = lookup.find(lower);
    if (it != lookup.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<Decision> ConfigLoader::parse_action(const std::string& action_str) {
    const std::string lower = utils::to_lower(action_str);
    if (lower == "allow") return Decision::ALLOW;
    if (lower == "block") return Decision::BLOCK;
    return std::nullopt;
}

// ---- Extract helpers (safe JSON access) ------------------------------------

namespace {

template<typename T>
T json_value(const nlohmann::json& obj, const std::string& key, const T& default_val) {
    if (obj.contains(key) && !obj[key].is_null()) {
        try {
            return obj[key].get<T>();
        } catch (...) {
            return default_val;
        }
    }
    return default_val;
}

// Specialization-like overloads for common types
std::string json_string(const nlohmann::json& obj, const std::string& key,
                        const std::string& default_val = "") {
    return json_value<std::string>(obj, key, default_val);
}

int json_int(const nlohmann::json& obj, const std::string& key, int default_val = 0) {
    if (obj.contains(key) && !obj[key].is_null()) {
        try {
            if (obj[key].is_number_integer()) {
                return static_cast<int>(obj[key].get<int64_t>());
            }
            if (obj[key].is_number_float()) {
                return static_cast<int>(obj[key].get<double>());
            }
        } catch (...) {}
    }
    return default_val;
}

uint32_t json_uint32(const nlohmann::json& obj, const std::string& key, uint32_t default_val = 0) {
    if (obj.contains(key) && !obj[key].is_null()) {
        try {
            if (obj[key].is_number_integer()) {
                return static_cast<uint32_t>(obj[key].get<int64_t>());
            }
        } catch (...) {}
    }
    return default_val;
}

size_t json_size(const nlohmann::json& obj, const std::string& key, size_t default_val = 0) {
    if (obj.contains(key) && !obj[key].is_null()) {
        try {
            if (obj[key].is_number_integer()) {
                return static_cast<size_t>(obj[key].get<int64_t>());
            }
        } catch (...) {}
    }
    return default_val;
}

bool json_bool(const nlohmann::json& obj, const std::string& key, bool default_val = false) {
    return json_value<bool>(obj, key, default_val);
}

double json_double(const nlohmann::json& obj, const std::string& key, double default_val = 0.0) {
    if (obj.contains(key) && !obj[key].is_null()) {
        try {
            if (obj[key].is_number()) {
                return obj[key].get<double>();
            }
        } catch (...) {}
    }
    return default_val;
}

std::vector<std::string> json_string_array(const nlohmann::json& obj, const std::string& key) {
    std::vector<std::string> result;
    if (!obj.contains(key) || !obj[key].is_array()) {
        return result;
    }
    const auto& arr = obj[key];
    result.reserve(arr.size());
    for (const auto& elem : arr) {
        if (elem.is_string()) {
            result.push_back(elem.get<std::string>());
        }
    }
    return result;
}

std::optional<std::string> json_optional_string(const nlohmann::json& obj, const std::string& key) {
    if (obj.contains(key) && obj[key].is_string()) {
        return obj[key].get<std::string>();
    }
    return std::nullopt;
}

} // anonymous namespace

// ---- Section extractors ----------------------------------------------------

ServerConfig ConfigLoader::extract_server(const nlohmann::json& root) {
    ServerConfig cfg;
    if (!root.contains("server")) {
        return cfg;
    }
    const auto& s = root["server"];
    cfg.host = json_string(s, "host", "0.0.0.0");
    cfg.port = static_cast<uint16_t>(json_int(s, "port", 8080));
    cfg.thread_pool_size = json_size(s, "threads", 4);
    cfg.request_timeout = std::chrono::milliseconds(
        json_int(s, "request_timeout_ms", 30000));
    return cfg;
}

LoggingConfig ConfigLoader::extract_logging(const nlohmann::json& root) {
    LoggingConfig cfg;
    if (!root.contains("logging")) {
        return cfg;
    }
    const auto& l = root["logging"];
    cfg.level = json_string(l, "level", "info");
    cfg.file = json_string(l, "file", "");
    cfg.async_logging = json_bool(l, "async", true);
    return cfg;
}

std::vector<DatabaseConfig> ConfigLoader::extract_databases(const nlohmann::json& root) {
    std::vector<DatabaseConfig> result;
    if (!root.contains("databases") || !root["databases"].is_array()) {
        return result;
    }
    const auto& arr = root["databases"];
    result.reserve(arr.size());
    for (const auto& db : arr) {
        DatabaseConfig cfg;
        cfg.name = json_string(db, "name", "default");
        cfg.connection_string = json_string(db, "connection_string", "");
        cfg.min_connections = json_size(db, "min_connections", 2);
        cfg.max_connections = json_size(db, "max_connections", 10);
        cfg.connection_timeout = std::chrono::milliseconds(
            json_int(db, "connection_timeout_ms", 5000));
        cfg.query_timeout = std::chrono::milliseconds(
            json_int(db, "query_timeout_ms", 30000));
        result.push_back(std::move(cfg));
    }
    return result;
}

std::unordered_map<std::string, UserInfo> ConfigLoader::extract_users(const nlohmann::json& root) {
    std::unordered_map<std::string, UserInfo> result;
    if (!root.contains("users") || !root["users"].is_array()) {
        return result;
    }
    const auto& arr = root["users"];
    for (const auto& u : arr) {
        UserInfo info;
        info.name = json_string(u, "name", "");
        if (info.name.empty()) {
            continue; // Skip unnamed users
        }
        info.roles = json_string_array(u, "roles");
        result.emplace(info.name, std::move(info));
    }
    return result;
}

std::vector<Policy> ConfigLoader::extract_policies(const nlohmann::json& root) {
    std::vector<Policy> result;
    if (!root.contains("policies") || !root["policies"].is_array()) {
        return result;
    }
    const auto& arr = root["policies"];
    result.reserve(arr.size());

    for (const auto& p : arr) {
        Policy policy;

        // Required: name
        policy.name = json_string(p, "name", "");
        if (policy.name.empty()) {
            continue; // Skip unnamed policies
        }

        // Required: priority
        policy.priority = json_int(p, "priority", 0);

        // Required: action
        const std::string action_str = json_string(p, "action", "BLOCK");
        const auto action = parse_action(action_str);
        policy.action = action.value_or(Decision::BLOCK);

        // Optional: users array
        const auto users = json_string_array(p, "users");
        for (const auto& user : users) {
            policy.users.insert(user);
        }

        // Optional: roles array
        const auto roles = json_string_array(p, "roles");
        for (const auto& role : roles) {
            policy.roles.insert(role);
        }

        // Optional: exclude_roles array
        const auto exclude_roles = json_string_array(p, "exclude_roles");
        for (const auto& role : exclude_roles) {
            policy.exclude_roles.insert(role);
        }

        // Optional: statement_types array
        const auto stmt_types = json_string_array(p, "statement_types");
        for (const auto& stmt_str : stmt_types) {
            const auto stmt_type = parse_statement_type(stmt_str);
            if (stmt_type.has_value()) {
                policy.scope.operations.insert(*stmt_type);
            }
        }

        // Optional: scope fields
        policy.scope.database = json_optional_string(p, "database");
        policy.scope.schema = json_optional_string(p, "schema");
        policy.scope.table = json_optional_string(p, "table");

        // Optional: reason
        policy.reason = json_string(p, "reason", "");

        result.push_back(std::move(policy));
    }

    return result;
}

RateLimitingConfig ConfigLoader::extract_rate_limiting(const nlohmann::json& root) {
    RateLimitingConfig cfg;
    if (!root.contains("rate_limiting")) {
        return cfg;
    }
    const auto& rl = root["rate_limiting"];

    cfg.enabled = json_bool(rl, "enabled", true);

    // Level 1: Global
    if (rl.contains("global") && rl["global"].is_object()) {
        const auto& g = rl["global"];
        cfg.global_tokens_per_second = json_uint32(g, "tokens_per_second", 50000);
        cfg.global_burst_capacity = json_uint32(g, "burst_capacity", 10000);
    }

    // Level 2: Per-User overrides
    if (rl.contains("per_user") && rl["per_user"].is_array()) {
        const auto& arr = rl["per_user"];
        cfg.per_user.reserve(arr.size());
        for (const auto& u : arr) {
            PerUserRateLimit limit;
            limit.user = json_string(u, "user", "");
            limit.tokens_per_second = json_uint32(u, "tokens_per_second", 100);
            limit.burst_capacity = json_uint32(u, "burst_capacity", 20);
            if (!limit.user.empty()) {
                cfg.per_user.push_back(std::move(limit));
            }
        }
    }

    // Per-User defaults
    if (rl.contains("per_user_default") && rl["per_user_default"].is_object()) {
        const auto& d = rl["per_user_default"];
        cfg.per_user_default_tokens_per_second = json_uint32(d, "tokens_per_second", 100);
        cfg.per_user_default_burst_capacity = json_uint32(d, "burst_capacity", 20);
    }

    // Level 3: Per-Database
    if (rl.contains("per_database") && rl["per_database"].is_array()) {
        const auto& arr = rl["per_database"];
        cfg.per_database.reserve(arr.size());
        for (const auto& db : arr) {
            PerDatabaseRateLimit limit;
            limit.database = json_string(db, "database", "");
            limit.tokens_per_second = json_uint32(db, "tokens_per_second", 30000);
            limit.burst_capacity = json_uint32(db, "burst_capacity", 5000);
            if (!limit.database.empty()) {
                cfg.per_database.push_back(std::move(limit));
            }
        }
    }

    // Level 4: Per-User-Per-Database
    if (rl.contains("per_user_per_database") && rl["per_user_per_database"].is_array()) {
        const auto& arr = rl["per_user_per_database"];
        cfg.per_user_per_database.reserve(arr.size());
        for (const auto& upd : arr) {
            PerUserPerDatabaseRateLimit limit;
            limit.user = json_string(upd, "user", "");
            limit.database = json_string(upd, "database", "");
            limit.tokens_per_second = json_uint32(upd, "tokens_per_second", 100);
            limit.burst_capacity = json_uint32(upd, "burst_capacity", 20);
            if (!limit.user.empty() && !limit.database.empty()) {
                cfg.per_user_per_database.push_back(std::move(limit));
            }
        }
    }

    return cfg;
}

CacheConfig ConfigLoader::extract_cache(const nlohmann::json& root) {
    CacheConfig cfg;
    if (!root.contains("cache")) {
        return cfg;
    }
    const auto& c = root["cache"];
    cfg.max_entries = json_size(c, "max_entries", 10000);
    cfg.num_shards = json_size(c, "num_shards", 16);
    cfg.ttl = std::chrono::seconds(json_int(c, "ttl_seconds", 300));
    return cfg;
}

AuditConfig ConfigLoader::extract_audit(const nlohmann::json& root) {
    AuditConfig cfg;
    if (!root.contains("audit")) {
        return cfg;
    }
    const auto& a = root["audit"];

    cfg.async_mode = json_bool(a, "async_mode", true);
    cfg.ring_buffer_size = json_size(a, "ring_buffer_size", 65536);
    cfg.batch_flush_interval = std::chrono::milliseconds(
        json_int(a, "flush_interval_ms", 1000));

    // File sink settings
    if (a.contains("file") && a["file"].is_object()) {
        const auto& f = a["file"];
        cfg.output_file = json_string(f, "output_file", "audit.jsonl");
    }

    // Database sink settings (batch_size and flush_interval_ms can also
    // come from the database sub-section; the top-level AuditConfig
    // captures only what the struct supports)
    if (a.contains("database") && a["database"].is_object()) {
        const auto& db = a["database"];
        // If there's a db-specific flush_interval_ms, prefer it
        const int db_flush = json_int(db, "flush_interval_ms", 0);
        if (db_flush > 0) {
            cfg.batch_flush_interval = std::chrono::milliseconds(db_flush);
        }
    }

    return cfg;
}

std::vector<ClassifierConfig> ConfigLoader::extract_classifiers(const nlohmann::json& root) {
    std::vector<ClassifierConfig> result;
    if (!root.contains("classifiers") || !root["classifiers"].is_array()) {
        return result;
    }
    const auto& arr = root["classifiers"];
    result.reserve(arr.size());

    for (const auto& c : arr) {
        ClassifierConfig cfg;
        cfg.type = json_string(c, "type", "");
        cfg.strategy = json_string(c, "strategy", "");
        cfg.patterns = json_string_array(c, "patterns");
        cfg.data_validation_regex = json_string(c, "data_validation_regex", "");
        cfg.sample_size = json_int(c, "sample_size", 0);
        cfg.confidence_threshold = json_double(c, "confidence_threshold", 0.0);

        if (!cfg.type.empty()) {
            result.push_back(std::move(cfg));
        }
    }

    return result;
}

CircuitBreakerConfig ConfigLoader::extract_circuit_breaker(const nlohmann::json& root) {
    CircuitBreakerConfig cfg;
    if (!root.contains("circuit_breaker")) {
        return cfg;
    }
    const auto& cb = root["circuit_breaker"];
    cfg.enabled = json_bool(cb, "enabled", true);
    cfg.failure_threshold = json_int(cb, "failure_threshold", 10);
    cfg.success_threshold = json_int(cb, "success_threshold", 5);
    cfg.timeout_ms = json_int(cb, "timeout_ms", 60000);
    cfg.half_open_max_calls = json_int(cb, "half_open_max_calls", 3);
    return cfg;
}

AllocatorConfig ConfigLoader::extract_allocator(const nlohmann::json& root) {
    AllocatorConfig cfg;
    if (!root.contains("allocator")) {
        return cfg;
    }
    const auto& a = root["allocator"];
    cfg.enabled = json_bool(a, "enabled", true);
    cfg.initial_size_bytes = json_size(a, "initial_size_bytes", 1024);
    cfg.max_size_bytes = json_size(a, "max_size_bytes", 65536);
    return cfg;
}

MetricsConfig ConfigLoader::extract_metrics(const nlohmann::json& root) {
    MetricsConfig cfg;
    if (!root.contains("metrics")) {
        return cfg;
    }
    const auto& m = root["metrics"];
    cfg.enabled = json_bool(m, "enabled", true);
    cfg.endpoint = json_string(m, "endpoint", "/metrics");
    cfg.export_interval_ms = json_int(m, "export_interval_ms", 5000);
    return cfg;
}

// ---- Public API ------------------------------------------------------------

ConfigLoader::LoadResult ConfigLoader::load_from_file(const std::string& config_path) {
    try {
        const auto json = toml::parse_file(config_path);
        ProxyConfig config;
        config.server = extract_server(json);
        config.logging = extract_logging(json);
        config.databases = extract_databases(json);
        config.users = extract_users(json);
        config.policies = extract_policies(json);
        config.rate_limiting = extract_rate_limiting(json);
        config.cache = extract_cache(json);
        config.audit = extract_audit(json);
        config.classifiers = extract_classifiers(json);
        config.circuit_breaker = extract_circuit_breaker(json);
        config.allocator = extract_allocator(json);
        config.metrics = extract_metrics(json);
        return LoadResult::ok(std::move(config));
    } catch (const std::exception& e) {
        return LoadResult::error(std::string("Failed to load config: ") + e.what());
    }
}

ConfigLoader::LoadResult ConfigLoader::load_from_string(const std::string& toml_content) {
    try {
        const auto json = toml::parse_string(toml_content);
        ProxyConfig config;
        config.server = extract_server(json);
        config.logging = extract_logging(json);
        config.databases = extract_databases(json);
        config.users = extract_users(json);
        config.policies = extract_policies(json);
        config.rate_limiting = extract_rate_limiting(json);
        config.cache = extract_cache(json);
        config.audit = extract_audit(json);
        config.classifiers = extract_classifiers(json);
        config.circuit_breaker = extract_circuit_breaker(json);
        config.allocator = extract_allocator(json);
        config.metrics = extract_metrics(json);
        return LoadResult::ok(std::move(config));
    } catch (const std::exception& e) {
        return LoadResult::error(std::string("Failed to parse config: ") + e.what());
    }
}

} // namespace sqlproxy
