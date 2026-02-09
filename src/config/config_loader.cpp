#include "config/config_loader.hpp"
#include "core/utils.hpp"

#include <format>
#include <fstream>
#include <stdexcept>
#include <algorithm>

namespace sqlproxy {

// ============================================================================
// TOML Parser Implementation
// ============================================================================

namespace toml {

namespace {

// Type aliases for internal TOML parser (uses glz::json_t directly for mutation)
using jt = glz::json_t;
using object_t = jt::object_t;
using array_t = jt::array_t;

// Helpers for creating json_t values
jt make_object() { jt j; j = object_t{}; return j; }
jt make_array() { jt j; j = array_t{}; return j; }
jt make_null() { return jt{}; }

void json_push(jt& arr, jt val) {
    arr.get_array().push_back(std::move(val));
}

jt& json_back(jt& arr) {
    return arr.get_array().back();
}

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
jt parse_value(const std::string& raw) {
    const std::string val = utils::trim(raw);
    if (val.empty()) {
        return make_null();
    }

    // Boolean
    if (val == "true")  { jt j; j = true; return j; }
    if (val == "false") { jt j; j = false; return j; }

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
        jt j; j = std::move(result); return j;
    }

    // Inline table  {key = "value", key2 = "value2"}
    if (val.front() == '{' && val.back() == '}') {
        jt obj = make_object();
        const std::string inner = val.substr(1, val.size() - 2);
        std::string token;
        bool in_str = false;
        bool esc = false;
        for (size_t i = 0; i < inner.size(); ++i) {
            const char c = inner[i];
            if (esc) { token += c; esc = false; continue; }
            if (c == '\\') { token += c; esc = true; continue; }
            if (c == '"') { token += c; in_str = !in_str; continue; }
            if (c == ',' && !in_str) {
                const auto eq = token.find('=');
                if (eq != std::string::npos) {
                    std::string k = utils::trim(token.substr(0, eq));
                    std::string v_str = utils::trim(token.substr(eq + 1));
                    obj[k] = parse_value(v_str);
                }
                token.clear();
                continue;
            }
            token += c;
        }
        const std::string last = utils::trim(token);
        if (!last.empty()) {
            const auto eq = last.find('=');
            if (eq != std::string::npos) {
                std::string k = utils::trim(last.substr(0, eq));
                std::string v_str = utils::trim(last.substr(eq + 1));
                obj[k] = parse_value(v_str);
            }
        }
        return obj;
    }

    // Inline array  ["a", "b", ...]
    if (val.front() == '[' && val.back() == ']') {
        jt arr = make_array();
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
                    json_push(arr, parse_value(trimmed));
                }
                token.clear();
                continue;
            }
            token += c;
        }
        const std::string trimmed = utils::trim(token);
        if (!trimmed.empty()) {
            json_push(arr, parse_value(trimmed));
        }
        return arr;
    }

    // Integer or float
    // Try integer first (no decimal point)
    if (val.find('.') == std::string::npos) {
        try {
            const long long int_val = std::stoll(val);
            jt j; j = static_cast<double>(int_val); return j;
        } catch (...) {
            // Fall through
        }
    }

    // Float
    try {
        const double float_val = std::stod(val);
        jt j; j = float_val; return j;
    } catch (...) {
        // Fall through
    }

    // Treat as bare string (shouldn't happen in valid TOML, but be lenient)
    jt j; j = val; return j;
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
jt& navigate_to(jt& root, const std::vector<std::string>& path) {
    jt* current = &root;
    for (const auto& segment : path) {
        if (!current->contains(segment)) {
            (*current)[segment] = make_object();
        }
        current = &(*current)[segment];
    }
    return *current;
}

} // anonymous namespace

JsonValue parse_string(const std::string& content) {
    jt root = make_object();

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
    jt* multiline_target = nullptr;

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
                jt value = parse_value(utils::trim(multiline_buffer));
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
                    std::format("TOML parse error at line {}: unclosed [[array]] header", line_num));
            }
            const std::string section_name = utils::trim(
                trimmed.substr(2, close - 2));

            array_section_path = parse_dotted_key(section_name);
            in_array_section = true;

            // Ensure the array exists in the JSON tree
            // Navigate to parent, then ensure the last key is an array
            jt* parent = &root;
            for (size_t i = 0; i + 1 < array_section_path.size(); ++i) {
                const auto& seg = array_section_path[i];
                if (!parent->contains(seg)) {
                    (*parent)[seg] = make_object();
                }
                parent = &(*parent)[seg];
            }

            const auto& array_key = array_section_path.back();
            if (!parent->contains(array_key)) {
                (*parent)[array_key] = make_array();
            }

            // Append a new empty object to the array
            json_push((*parent)[array_key], make_object());

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
        jt* target = nullptr;
        if (in_array_section) {
            // Navigate to the parent of the array, get the array, index last element
            jt* parent = &root;
            for (size_t i = 0; i + 1 < array_section_path.size(); ++i) {
                parent = &(*parent)[array_section_path[i]];
            }
            auto& arr = (*parent)[array_section_path.back()];
            target = &json_back(arr);
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
        jt value = parse_value(value_str);
        (*target)[key] = std::move(value);
    }

    if (in_multiline_array) {
        throw std::runtime_error(
            "TOML parse error: unterminated multi-line array for key '" +
            multiline_key + "'");
    }

    return JsonValue(std::move(root));
}

JsonValue parse_file(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        throw std::runtime_error(
            std::format("Cannot open TOML file: {}", file_path));
    }

    std::string buffer((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());
    return parse_string(buffer);
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

    static const std::unordered_map<std::string, Decision> lookup = {
        {"allow", Decision::ALLOW},
        {"block", Decision::BLOCK},
    };

    const auto it = lookup.find(lower);
    return (it != lookup.end()) ? std::make_optional(it->second) : std::nullopt;
}

// ---- Extract helpers (safe JSON access) ------------------------------------

namespace {

template<typename T>
T json_value(const JsonValue& obj, std::string_view key, const T& default_val) {
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
std::string json_string(const JsonValue& obj, std::string_view key,
                        const std::string& default_val = "") {
    return json_value<std::string>(obj, key, default_val);
}

int json_int(const JsonValue& obj, std::string_view key, int default_val = 0) {
    if (obj.contains(key) && !obj[key].is_null()) {
        try {
            auto val = obj[key];
            if (val.is_number_integer()) {
                return static_cast<int>(val.get<int64_t>());
            }
            if (val.is_number_float()) {
                return static_cast<int>(val.get<double>());
            }
            if (val.is_number()) {
                return static_cast<int>(val.get<double>());
            }
        } catch (...) {}
    }
    return default_val;
}

uint32_t json_uint32(const JsonValue& obj, std::string_view key, uint32_t default_val = 0) {
    if (obj.contains(key) && !obj[key].is_null()) {
        try {
            auto val = obj[key];
            if (val.is_number()) {
                return static_cast<uint32_t>(val.get<int64_t>());
            }
        } catch (...) {}
    }
    return default_val;
}

size_t json_size(const JsonValue& obj, std::string_view key, size_t default_val = 0) {
    if (obj.contains(key) && !obj[key].is_null()) {
        try {
            auto val = obj[key];
            if (val.is_number()) {
                return static_cast<size_t>(val.get<int64_t>());
            }
        } catch (...) {}
    }
    return default_val;
}

bool json_bool(const JsonValue& obj, std::string_view key, bool default_val = false) {
    return json_value<bool>(obj, key, default_val);
}

double json_double(const JsonValue& obj, std::string_view key, double default_val = 0.0) {
    if (obj.contains(key) && !obj[key].is_null()) {
        try {
            auto val = obj[key];
            if (val.is_number()) {
                return val.get<double>();
            }
        } catch (...) {}
    }
    return default_val;
}

std::vector<std::string> json_string_array(const JsonValue& obj, std::string_view key) {
    std::vector<std::string> result;
    if (!obj.contains(key) || !obj[key].is_array()) {
        return result;
    }
    const auto arr = obj[key];
    result.reserve(arr.size());
    for (const auto& elem : arr) {
        if (elem.is_string()) {
            result.push_back(elem.get<std::string>());
        }
    }
    return result;
}

std::optional<std::string> json_optional_string(const JsonValue& obj, std::string_view key) {
    if (obj.contains(key) && obj[key].is_string()) {
        return obj[key].get<std::string>();
    }
    return std::nullopt;
}

} // anonymous namespace

// Constexpr config keys (used 2+ times across section extractors)
static constexpr std::string_view kDatabases         = "databases";
static constexpr std::string_view kUsers             = "users";
static constexpr std::string_view kPolicies          = "policies";
static constexpr std::string_view kClassifiers       = "classifiers";
static constexpr std::string_view kGlobal            = "global";
static constexpr std::string_view kPerUser           = "per_user";
static constexpr std::string_view kPerUserDefault    = "per_user_default";
static constexpr std::string_view kPerDatabase       = "per_database";
static constexpr std::string_view kPerUserPerDatabase = "per_user_per_database";
static constexpr std::string_view kTokensPerSecond   = "tokens_per_second";
static constexpr std::string_view kBurstCapacity     = "burst_capacity";
static constexpr std::string_view kEnabled           = "enabled";
static constexpr std::string_view kDatabase          = "database";
static constexpr std::string_view kFile              = "file";
static constexpr std::string_view kFlushIntervalMs   = "flush_interval_ms";
static constexpr std::string_view kName              = "name";
static constexpr std::string_view kUser              = "user";
static constexpr std::string_view kRoles             = "roles";
static constexpr std::string_view kType              = "type";

// ---- Section extractors ----------------------------------------------------

ServerConfig ConfigLoader::extract_server(const JsonValue& root) {
    ServerConfig cfg;
    if (!root.contains("server")) {
        return cfg;
    }
    const auto s = root["server"];
    cfg.host = json_string(s, "host", "0.0.0.0");
    cfg.port = static_cast<uint16_t>(json_int(s, "port", 8080));
    cfg.thread_pool_size = json_size(s, "threads", 4);
    cfg.request_timeout = std::chrono::milliseconds(
        json_int(s, "request_timeout_ms", 30000));
    cfg.admin_token = json_string(s, "admin_token", "");
    cfg.max_sql_length = json_size(s, "max_sql_length", 102400);

    // TLS/mTLS
    if (s.contains("tls") && s["tls"].is_object()) {
        const auto t = s["tls"];
        cfg.tls.enabled = json_bool(t, kEnabled, false);
        cfg.tls.cert_file = json_string(t, "cert_file", "");
        cfg.tls.key_file = json_string(t, "key_file", "");
        cfg.tls.ca_file = json_string(t, "ca_file", "");
        cfg.tls.require_client_cert = json_bool(t, "require_client_cert", false);
    }

    // Tier B: Graceful shutdown + compression
    cfg.shutdown_timeout_ms = static_cast<uint32_t>(json_int(s, "shutdown_timeout_ms", 30000));
    cfg.compression_enabled = json_bool(s, "compression_enabled", false);
    cfg.compression_min_size_bytes = json_size(s, "compression_min_size_bytes", 1024);

    return cfg;
}

LoggingConfig ConfigLoader::extract_logging(const JsonValue& root) {
    LoggingConfig cfg;
    if (!root.contains("logging")) {
        return cfg;
    }
    const auto l = root["logging"];
    cfg.level = json_string(l, "level", "info");
    cfg.file = json_string(l, "file", "");
    cfg.async_logging = json_bool(l, "async", true);
    return cfg;
}

std::vector<DatabaseConfig> ConfigLoader::extract_databases(const JsonValue& root) {
    std::vector<DatabaseConfig> result;
    if (!root.contains(kDatabases) || !root[kDatabases].is_array()) {
        return result;
    }
    const auto arr = root[kDatabases];
    result.reserve(arr.size());
    for (const auto& db : arr) {
        DatabaseConfig cfg;
        cfg.name = json_string(db, kName, "default");
        cfg.type_str = json_string(db, kType, "postgresql");
        cfg.connection_string = json_string(db, "connection_string", "");
        cfg.min_connections = json_size(db, "min_connections", 2);
        cfg.max_connections = json_size(db, "max_connections", 10);
        cfg.connection_timeout = std::chrono::milliseconds(
            json_int(db, "connection_timeout_ms", 5000));
        cfg.query_timeout = std::chrono::milliseconds(
            json_int(db, "query_timeout_ms", 30000));
        cfg.health_check_query = json_string(db, "health_check_query", "SELECT 1");
        cfg.health_check_interval_seconds = json_int(db, "health_check_interval_seconds", 10);
        cfg.idle_timeout_seconds = json_int(db, "idle_timeout_seconds", 300);
        cfg.pool_acquire_timeout_ms = json_int(db, "pool_acquire_timeout_ms", 5000);
        cfg.max_result_rows = json_size(db, "max_result_rows", 10000);

        // Parse replicas for read/write splitting
        if (db.contains("replicas") && db["replicas"].is_array()) {
            const auto replicas_arr = db["replicas"];
            cfg.replicas.reserve(replicas_arr.size());
            for (const auto& r : replicas_arr) {
                ReplicaConfig replica;
                replica.connection_string = json_string(r, "connection_string", "");
                replica.min_connections = json_size(r, "min_connections", 2);
                replica.max_connections = json_size(r, "max_connections", 5);
                replica.connection_timeout = std::chrono::milliseconds(
                    json_int(r, "connection_timeout_ms", 5000));
                replica.health_check_query = json_string(r, "health_check_query", "SELECT 1");
                replica.weight = json_int(r, "weight", 1);
                if (!replica.connection_string.empty()) {
                    cfg.replicas.push_back(std::move(replica));
                }
            }
        }

        result.push_back(std::move(cfg));
    }
    return result;
}

std::unordered_map<std::string, UserInfo> ConfigLoader::extract_users(const JsonValue& root) {
    std::unordered_map<std::string, UserInfo> result;
    if (!root.contains(kUsers) || !root[kUsers].is_array()) {
        return result;
    }
    const auto arr = root[kUsers];
    for (const auto& u : arr) {
        std::string name = json_string(u, kName, "");
        if (name.empty()) {
            continue; // Skip unnamed users
        }
        auto roles = json_string_array(u, kRoles);
        std::string api_key = json_string(u, "api_key", "");

        UserInfo info(std::move(name), std::move(roles), std::move(api_key));

        // Parse default_database
        std::string default_db = json_string(u, "default_database", "");
        if (!default_db.empty()) {
            info.default_database = std::move(default_db);
        }

        // Parse attributes (inline table → key/value pairs for RLS)
        auto attrs = u["attributes"];
        if (attrs.is_object()) {
            for (const auto& [k, v] : attrs.items()) {
                if (v.is_string()) {
                    info.attributes[k] = v.get<std::string>();
                }
            }
        }

        result.emplace(info.name, std::move(info));
    }
    return result;
}

std::vector<Policy> ConfigLoader::extract_policies(const JsonValue& root) {
    std::vector<Policy> result;
    if (!root.contains(kPolicies) || !root[kPolicies].is_array()) {
        return result;
    }
    const auto arr = root[kPolicies];
    result.reserve(arr.size());

    for (const auto& p : arr) {
        Policy policy;

        // Required: name
        policy.name = json_string(p, kName, "");
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
        const auto users = json_string_array(p, kUsers);
        for (const auto& user : users) {
            policy.users.insert(user);
        }

        // Optional: roles array
        const auto roles = json_string_array(p, kRoles);
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
        policy.scope.database = json_optional_string(p, kDatabase);
        policy.scope.schema = json_optional_string(p, "schema");
        policy.scope.table = json_optional_string(p, "table");

        // Optional: columns array (column-level ACL)
        policy.scope.columns = json_string_array(p, "columns");

        // Optional: masking fields
        if (p.contains("masking_action")) {
            static const std::unordered_map<std::string, MaskingAction> masking_lookup = {
                {"none", MaskingAction::NONE},
                {"redact", MaskingAction::REDACT},
                {"partial", MaskingAction::PARTIAL},
                {"hash", MaskingAction::HASH},
                {"nullify", MaskingAction::NULLIFY},
            };
            const std::string masking_str = utils::to_lower(json_string(p, "masking_action", "none"));
            const auto mit = masking_lookup.find(masking_str);
            if (mit != masking_lookup.end()) {
                policy.masking_action = mit->second;
            }
        }
        policy.masking_prefix_len = json_int(p, "masking_prefix_len", 3);
        policy.masking_suffix_len = json_int(p, "masking_suffix_len", 3);

        // Optional: reason
        policy.reason = json_string(p, "reason", "");

        // Optional: shadow mode (log-only, don't enforce)
        policy.shadow = json_bool(p, "shadow", false);

        result.push_back(std::move(policy));
    }

    return result;
}

RateLimitingConfig ConfigLoader::extract_rate_limiting(const JsonValue& root) {
    RateLimitingConfig cfg;
    if (!root.contains("rate_limiting")) {
        return cfg;
    }
    const auto rl = root["rate_limiting"];

    cfg.enabled = json_bool(rl, kEnabled, true);

    // Level 1: Global
    if (rl.contains(kGlobal) && rl[kGlobal].is_object()) {
        const auto g = rl[kGlobal];
        cfg.global_tokens_per_second = json_uint32(g, kTokensPerSecond, 50000);
        cfg.global_burst_capacity = json_uint32(g, kBurstCapacity, 10000);
    }

    // Level 2: Per-User overrides
    if (rl.contains(kPerUser) && rl[kPerUser].is_array()) {
        const auto arr = rl[kPerUser];
        cfg.per_user.reserve(arr.size());
        for (const auto& u : arr) {
            PerUserRateLimit limit;
            limit.user = json_string(u, kUser, "");
            limit.tokens_per_second = json_uint32(u, kTokensPerSecond, 100);
            limit.burst_capacity = json_uint32(u, kBurstCapacity, 20);
            if (!limit.user.empty()) {
                cfg.per_user.push_back(std::move(limit));
            }
        }
    }

    // Per-User defaults
    if (rl.contains(kPerUserDefault) && rl[kPerUserDefault].is_object()) {
        const auto d = rl[kPerUserDefault];
        cfg.per_user_default_tokens_per_second = json_uint32(d, kTokensPerSecond, 100);
        cfg.per_user_default_burst_capacity = json_uint32(d, kBurstCapacity, 20);
    }

    // Level 3: Per-Database
    if (rl.contains(kPerDatabase) && rl[kPerDatabase].is_array()) {
        const auto arr = rl[kPerDatabase];
        cfg.per_database.reserve(arr.size());
        for (const auto& db : arr) {
            PerDatabaseRateLimit limit;
            limit.database = json_string(db, kDatabase, "");
            limit.tokens_per_second = json_uint32(db, kTokensPerSecond, 30000);
            limit.burst_capacity = json_uint32(db, kBurstCapacity, 5000);
            if (!limit.database.empty()) {
                cfg.per_database.push_back(std::move(limit));
            }
        }
    }

    // Level 4: Per-User-Per-Database
    if (rl.contains(kPerUserPerDatabase) && rl[kPerUserPerDatabase].is_array()) {
        const auto arr = rl[kPerUserPerDatabase];
        cfg.per_user_per_database.reserve(arr.size());
        for (const auto& upd : arr) {
            PerUserPerDatabaseRateLimit limit;
            limit.user = json_string(upd, kUser, "");
            limit.database = json_string(upd, kDatabase, "");
            limit.tokens_per_second = json_uint32(upd, kTokensPerSecond, 100);
            limit.burst_capacity = json_uint32(upd, kBurstCapacity, 20);
            if (!limit.user.empty() && !limit.database.empty()) {
                cfg.per_user_per_database.push_back(std::move(limit));
            }
        }
    }

    // Request queuing (backpressure)
    if (rl.contains("queue") && rl["queue"].is_object()) {
        const auto q = rl["queue"];
        cfg.queue_enabled = json_bool(q, kEnabled, false);
        cfg.queue_timeout_ms = json_uint32(q, "timeout_ms", 5000);
        cfg.max_queue_depth = json_uint32(q, "max_depth", 1000);
    }

    return cfg;
}

CacheConfig ConfigLoader::extract_cache(const JsonValue& root) {
    CacheConfig cfg;
    if (!root.contains("cache")) {
        return cfg;
    }
    const auto c = root["cache"];
    cfg.max_entries = json_size(c, "max_entries", 10000);
    cfg.num_shards = json_size(c, "num_shards", 16);
    cfg.ttl = std::chrono::seconds(json_int(c, "ttl_seconds", 300));
    return cfg;
}

AuditConfig ConfigLoader::extract_audit(const JsonValue& root) {
    AuditConfig cfg;
    if (!root.contains("audit")) {
        return cfg;
    }
    const auto a = root["audit"];

    cfg.async_mode = json_bool(a, "async_mode", true);
    cfg.ring_buffer_size = json_size(a, "ring_buffer_size", 65536);
    cfg.batch_flush_interval = std::chrono::milliseconds(
        json_int(a, kFlushIntervalMs, 1000));
    cfg.max_batch_size = json_size(a, "max_batch_size", 1000);
    cfg.fsync_interval_batches = json_int(a, "fsync_interval_batches", 10);

    // File sink settings
    if (a.contains(kFile) && a[kFile].is_object()) {
        const auto f = a[kFile];
        cfg.output_file = json_string(f, "output_file", "audit.jsonl");
    }

    // Database sink settings (batch_size and flush_interval_ms can also
    // come from the database sub-section; the top-level AuditConfig
    // captures only what the struct supports)
    if (a.contains(kDatabase) && a[kDatabase].is_object()) {
        const auto db = a[kDatabase];
        // If there's a db-specific flush_interval_ms, prefer it
        const int db_flush = json_int(db, kFlushIntervalMs, 0);
        if (db_flush > 0) {
            cfg.batch_flush_interval = std::chrono::milliseconds(db_flush);
        }
    }

    // Rotation settings
    if (a.contains("rotation") && a["rotation"].is_object()) {
        const auto r = a["rotation"];
        cfg.rotation_max_file_size_mb = json_size(r, "max_file_size_mb", 100);
        cfg.rotation_max_files = json_int(r, "max_files", 10);
        cfg.rotation_interval_hours = json_int(r, "interval_hours", 24);
        cfg.rotation_time_based = json_bool(r, "time_based", true);
        cfg.rotation_size_based = json_bool(r, "size_based", true);
    }

    // Webhook sink settings
    if (a.contains("webhook") && a["webhook"].is_object()) {
        const auto w = a["webhook"];
        cfg.webhook_enabled = json_bool(w, "enabled", false);
        cfg.webhook_url = json_string(w, "url", "");
        cfg.webhook_auth_header = json_string(w, "auth_header", "");
        cfg.webhook_timeout_ms = json_int(w, "timeout_ms", 5000);
        cfg.webhook_max_retries = json_int(w, "max_retries", 3);
        cfg.webhook_batch_size = json_int(w, "batch_size", 100);
    }

    // Syslog sink settings
    if (a.contains("syslog") && a["syslog"].is_object()) {
        const auto s = a["syslog"];
        cfg.syslog_enabled = json_bool(s, "enabled", false);
        cfg.syslog_ident = json_string(s, "ident", "sql-proxy");
    }

    // Integrity (hash chain) settings
    if (a.contains("integrity") && a["integrity"].is_object()) {
        const auto i = a["integrity"];
        cfg.integrity_enabled = json_bool(i, kEnabled, true);
        cfg.integrity_algorithm = json_string(i, "algorithm", "sha256");
    }

    return cfg;
}

std::vector<ClassifierConfig> ConfigLoader::extract_classifiers(const JsonValue& root) {
    std::vector<ClassifierConfig> result;
    if (!root.contains(kClassifiers) || !root[kClassifiers].is_array()) {
        return result;
    }
    const auto arr = root[kClassifiers];
    result.reserve(arr.size());

    for (const auto& c : arr) {
        ClassifierConfig cfg;
        cfg.type = json_string(c, kType, "");
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

CircuitBreakerConfig ConfigLoader::extract_circuit_breaker(const JsonValue& root) {
    CircuitBreakerConfig cfg;
    if (!root.contains("circuit_breaker")) {
        return cfg;
    }
    const auto cb = root["circuit_breaker"];
    cfg.enabled = json_bool(cb, kEnabled, true);
    cfg.failure_threshold = json_int(cb, "failure_threshold", 10);
    cfg.success_threshold = json_int(cb, "success_threshold", 5);
    cfg.timeout_ms = json_int(cb, "timeout_ms", 60000);
    cfg.half_open_max_calls = json_int(cb, "half_open_max_calls", 3);
    return cfg;
}

AllocatorConfig ConfigLoader::extract_allocator(const JsonValue& root) {
    AllocatorConfig cfg;
    if (!root.contains("allocator")) {
        return cfg;
    }
    const auto a = root["allocator"];
    cfg.enabled = json_bool(a, kEnabled, true);
    cfg.initial_size_bytes = json_size(a, "initial_size_bytes", 1024);
    cfg.max_size_bytes = json_size(a, "max_size_bytes", 65536);
    return cfg;
}

MetricsConfig ConfigLoader::extract_metrics(const JsonValue& root) {
    MetricsConfig cfg;
    if (!root.contains("metrics")) {
        return cfg;
    }
    const auto m = root["metrics"];
    cfg.enabled = json_bool(m, kEnabled, true);
    cfg.endpoint = json_string(m, "endpoint", "/metrics");
    cfg.export_interval_ms = json_int(m, "export_interval_ms", 5000);
    return cfg;
}

ConfigWatcherConfig ConfigLoader::extract_config_watcher(const JsonValue& root) {
    ConfigWatcherConfig cfg;
    if (!root.contains("config_watcher")) {
        return cfg;
    }
    const auto cw = root["config_watcher"];
    cfg.enabled = json_bool(cw, kEnabled, true);
    cfg.poll_interval_seconds = json_int(cw, "poll_interval_seconds", 5);
    return cfg;
}

SecurityConfig ConfigLoader::extract_security(const JsonValue& root) {
    SecurityConfig cfg;
    if (!root.contains("security")) {
        return cfg;
    }
    const auto s = root["security"];
    cfg.injection_detection_enabled = json_bool(s, "injection_detection", true);
    cfg.anomaly_detection_enabled = json_bool(s, "anomaly_detection", true);
    cfg.lineage_tracking_enabled = json_bool(s, "lineage_tracking", true);
    return cfg;
}

EncryptionConfig ConfigLoader::extract_encryption(const JsonValue& root) {
    EncryptionConfig cfg;
    if (!root.contains("encryption")) {
        return cfg;
    }
    const auto e = root["encryption"];
    cfg.enabled = json_bool(e, kEnabled, false);
    cfg.key_file = json_string(e, "key_file", "config/encryption_keys.json");

    if (e.contains("columns") && e["columns"].is_array()) {
        const auto arr = e["columns"];
        cfg.columns.reserve(arr.size());
        for (const auto& c : arr) {
            EncryptionColumnConfigEntry entry;
            entry.database = json_string(c, kDatabase, "");
            entry.table = json_string(c, "table", "");
            entry.column = json_string(c, "column", "");
            if (!entry.column.empty()) {
                cfg.columns.push_back(std::move(entry));
            }
        }
    }

    // Key manager provider
    if (e.contains("key_manager") && e["key_manager"].is_object()) {
        const auto km = e["key_manager"];
        cfg.key_manager_provider = json_string(km, "provider", "local");
        cfg.vault_addr = json_string(km, "vault_addr", "");
        cfg.vault_token = json_string(km, "vault_token", "");
        cfg.vault_key_name = json_string(km, "vault_key_name", "sql-proxy");
        cfg.vault_mount = json_string(km, "vault_mount", "transit");
        cfg.vault_cache_ttl_seconds = json_int(km, "vault_cache_ttl_seconds", 300);
        cfg.env_key_var = json_string(km, "env_key_var", "ENCRYPTION_KEY");
    }

    return cfg;
}

// ---- RLS & Rewrite Rule extractors -----------------------------------------

namespace {

std::vector<RlsRule> extract_rls_rules(const JsonValue& root) {
    std::vector<RlsRule> result;
    if (!root.contains("row_level_security") || !root["row_level_security"].is_array()) {
        return result;
    }
    const auto arr = root["row_level_security"];
    result.reserve(arr.size());
    for (const auto& r : arr) {
        RlsRule rule;
        rule.name = json_string(r, "name", "");
        if (rule.name.empty()) continue;
        rule.database = json_optional_string(r, "database");
        rule.table = json_optional_string(r, "table");
        rule.condition = json_string(r, "condition", "");
        rule.users = json_string_array(r, "users");
        rule.roles = json_string_array(r, "roles");
        if (!rule.condition.empty()) {
            result.push_back(std::move(rule));
        }
    }
    return result;
}

std::vector<RewriteRule> extract_rewrite_rules(const JsonValue& root) {
    std::vector<RewriteRule> result;
    if (!root.contains("rewrite_rules") || !root["rewrite_rules"].is_array()) {
        return result;
    }
    const auto arr = root["rewrite_rules"];
    result.reserve(arr.size());
    for (const auto& r : arr) {
        RewriteRule rule;
        rule.name = json_string(r, "name", "");
        if (rule.name.empty()) continue;
        rule.type = json_string(r, "type", "");
        rule.limit_value = json_int(r, "limit_value", 1000);
        rule.users = json_string_array(r, "users");
        rule.roles = json_string_array(r, "roles");
        if (!rule.type.empty()) {
            result.push_back(std::move(rule));
        }
    }
    return result;
}

} // anonymous namespace

// ---- Tier 5 extractors -----------------------------------------------------

TenantConfigEntry ConfigLoader::extract_tenants(const JsonValue& root) {
    TenantConfigEntry cfg;
    if (!root.contains("tenants")) return cfg;
    const auto t = root["tenants"];
    cfg.enabled = json_bool(t, kEnabled, false);
    cfg.default_tenant = json_string(t, "default_tenant", "default");
    cfg.header_name = json_string(t, "header_name", "X-Tenant-Id");
    return cfg;
}

std::vector<PluginConfigEntry> ConfigLoader::extract_plugins(const JsonValue& root) {
    std::vector<PluginConfigEntry> result;
    if (!root.contains("plugins") || !root["plugins"].is_array()) return result;
    const auto arr = root["plugins"];
    result.reserve(arr.size());
    for (const auto& p : arr) {
        PluginConfigEntry entry;
        entry.path = json_string(p, "path", "");
        entry.type = json_string(p, kType, "");
        entry.config = json_string(p, "config", "");
        if (!entry.path.empty() && !entry.type.empty()) {
            result.push_back(std::move(entry));
        }
    }
    return result;
}

SchemaManagementConfigEntry ConfigLoader::extract_schema_management(const JsonValue& root) {
    SchemaManagementConfigEntry cfg;
    if (!root.contains("schema_management")) return cfg;
    const auto s = root["schema_management"];
    cfg.enabled = json_bool(s, kEnabled, false);
    cfg.require_approval = json_bool(s, "require_approval", false);
    cfg.max_history_entries = json_size(s, "max_history_entries", 1000);
    return cfg;
}

WireProtocolConfigEntry ConfigLoader::extract_wire_protocol(const JsonValue& root) {
    WireProtocolConfigEntry cfg;
    if (!root.contains("wire_protocol")) return cfg;
    const auto w = root["wire_protocol"];
    cfg.enabled = json_bool(w, kEnabled, false);
    cfg.host = json_string(w, "host", "0.0.0.0");
    cfg.port = static_cast<uint16_t>(json_int(w, "port", 5433));
    cfg.max_connections = json_uint32(w, "max_connections", 100);
    cfg.thread_pool_size = json_uint32(w, "thread_pool_size", 4);
    cfg.require_password = json_bool(w, "require_password", false);
    return cfg;
}

GraphQLConfigEntry ConfigLoader::extract_graphql(const JsonValue& root) {
    GraphQLConfigEntry cfg;
    if (!root.contains("graphql")) return cfg;
    const auto g = root["graphql"];
    cfg.enabled = json_bool(g, kEnabled, false);
    cfg.endpoint = json_string(g, "endpoint", "/api/v1/graphql");
    cfg.max_query_depth = json_uint32(g, "max_query_depth", 5);
    return cfg;
}

BinaryRpcConfigEntry ConfigLoader::extract_binary_rpc(const JsonValue& root) {
    BinaryRpcConfigEntry cfg;
    if (!root.contains("binary_rpc")) return cfg;
    const auto b = root["binary_rpc"];
    cfg.enabled = json_bool(b, kEnabled, false);
    cfg.host = json_string(b, "host", "0.0.0.0");
    cfg.port = static_cast<uint16_t>(json_int(b, "port", 9090));
    cfg.max_connections = json_uint32(b, "max_connections", 50);
    return cfg;
}

AlertingConfig ConfigLoader::extract_alerting(const JsonValue& root) {
    AlertingConfig cfg;
    if (!root.contains("alerting")) return cfg;
    const auto a = root["alerting"];

    cfg.enabled = json_bool(a, kEnabled, false);
    cfg.evaluation_interval_seconds = json_int(a, "evaluation_interval_seconds", 10);
    cfg.alert_log_file = json_string(a, "alert_log_file", "alerts.jsonl");

    // Webhook
    if (a.contains("webhook") && a["webhook"].is_object()) {
        const auto w = a["webhook"];
        cfg.webhook.enabled = json_bool(w, kEnabled, false);
        cfg.webhook.url = json_string(w, "url", "");
        cfg.webhook.auth_header = json_string(w, "auth_header", "");
    }

    // Rules
    if (a.contains("rules") && a["rules"].is_array()) {
        const auto rules_arr = a["rules"];
        for (const auto& r : rules_arr) {
            AlertRule rule;
            rule.name = json_string(r, kName, "");
            rule.condition = parse_alert_condition(json_string(r, "condition", "custom_metric"));
            rule.threshold = static_cast<double>(json_int(r, "threshold", 0));
            rule.window = std::chrono::seconds(json_int(r, "window_seconds", 60));
            rule.cooldown = std::chrono::seconds(json_int(r, "cooldown_seconds", 300));
            rule.severity = json_string(r, "severity", "warning");
            rule.enabled = json_bool(r, kEnabled, true);
            cfg.rules.push_back(std::move(rule));
        }
    }

    return cfg;
}

AuthConfig ConfigLoader::extract_auth(const JsonValue& root) {
    AuthConfig cfg;
    if (!root.contains("auth")) {
        return cfg;
    }
    const auto a = root["auth"];
    cfg.provider = json_string(a, "provider", "api_key");

    // JWT sub-section
    if (a.contains("jwt") && a["jwt"].is_object()) {
        const auto j = a["jwt"];
        cfg.jwt_issuer = json_string(j, "issuer", "");
        cfg.jwt_audience = json_string(j, "audience", "");
        cfg.jwt_secret = json_string(j, "secret", "");
        cfg.jwt_roles_claim = json_string(j, "roles_claim", "roles");
    }

    // LDAP sub-section
    if (a.contains("ldap") && a["ldap"].is_object()) {
        const auto l = a["ldap"];
        cfg.ldap_url = json_string(l, "url", "");
        cfg.ldap_base_dn = json_string(l, "base_dn", "");
        cfg.ldap_bind_dn = json_string(l, "bind_dn", "");
        cfg.ldap_bind_password = json_string(l, "bind_password", "");
        cfg.ldap_user_filter = json_string(l, "user_filter", "(uid={})");
        cfg.ldap_group_attribute = json_string(l, "group_attribute", "memberOf");
    }

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
        config.config_watcher = extract_config_watcher(json);
        config.rls_rules = extract_rls_rules(json);
        config.rewrite_rules = extract_rewrite_rules(json);
        config.security = extract_security(json);
        config.encryption = extract_encryption(json);
        config.tenants = extract_tenants(json);
        config.plugins = extract_plugins(json);
        config.schema_management = extract_schema_management(json);
        config.wire_protocol = extract_wire_protocol(json);
        config.graphql = extract_graphql(json);
        config.binary_rpc = extract_binary_rpc(json);
        config.alerting = extract_alerting(json);
        config.auth = extract_auth(json);
        config.audit_sampling = extract_audit_sampling(json);
        config.result_cache = extract_result_cache(json);
        return LoadResult::ok(std::move(config));
    } catch (const std::exception& e) {
        return LoadResult::error(std::format("Failed to load config: {}", e.what()));
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
        config.config_watcher = extract_config_watcher(json);
        config.rls_rules = extract_rls_rules(json);
        config.rewrite_rules = extract_rewrite_rules(json);
        config.security = extract_security(json);
        config.encryption = extract_encryption(json);
        config.alerting = extract_alerting(json);
        config.auth = extract_auth(json);
        config.audit_sampling = extract_audit_sampling(json);
        config.result_cache = extract_result_cache(json);
        return LoadResult::ok(std::move(config));
    } catch (const std::exception& e) {
        return LoadResult::error(std::format("Failed to parse config: {}", e.what()));
    }
}

// ============================================================================
// Tier B extractors
// ============================================================================

ProxyConfig::AuditSamplingConfig ConfigLoader::extract_audit_sampling(const JsonValue& root) {
    ProxyConfig::AuditSamplingConfig cfg;
    if (!root.contains("audit")) return cfg;
    const auto a = root["audit"];
    if (!a.contains("sampling") || !a["sampling"].is_object()) return cfg;
    const auto s = a["sampling"];

    cfg.enabled = json_bool(s, kEnabled, false);
    cfg.default_sample_rate = json_double(s, "default_sample_rate", 1.0);
    cfg.select_sample_rate = json_double(s, "select_sample_rate", 1.0);
    cfg.always_log_blocked = json_bool(s, "always_log_blocked", true);
    cfg.always_log_writes = json_bool(s, "always_log_writes", true);
    cfg.always_log_errors = json_bool(s, "always_log_errors", true);
    cfg.deterministic = json_bool(s, "deterministic", true);
    return cfg;
}

ProxyConfig::ResultCacheConfig ConfigLoader::extract_result_cache(const JsonValue& root) {
    ProxyConfig::ResultCacheConfig cfg;
    if (!root.contains("result_cache")) return cfg;
    const auto c = root["result_cache"];

    cfg.enabled = json_bool(c, kEnabled, false);
    cfg.max_entries = json_size(c, "max_entries", 5000);
    cfg.num_shards = json_size(c, "num_shards", 16);
    cfg.ttl_seconds = json_int(c, "ttl_seconds", 60);
    cfg.max_result_size_bytes = json_size(c, "max_result_size_bytes", 1048576);
    return cfg;
}

} // namespace sqlproxy
