#include "config/config_loader.hpp"
#include "core/utils.hpp"

#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <stdexcept>
#include <algorithm>
#include <unordered_set>

using namespace std::string_literals;

namespace sqlproxy {

// ============================================================================
// TOML Parsing Helpers (env expansion, includes, merging)
// ============================================================================

namespace {

/**
 * @brief Expand ${VAR_NAME} patterns in a string with environment variables.
 */
std::string expand_env_vars(const std::string& input) {
    if (input.find("${") == std::string::npos) return input;

    std::string result;
    result.reserve(input.size());
    size_t i = 0;
    while (i < input.size()) {
        if (i + 1 < input.size() && input[i] == '$' && input[i + 1] == '{') {
            const size_t close = input.find('}', i + 2);
            if (close == std::string::npos) {
                throw std::runtime_error(
                    std::format("Unclosed env var substitution at position {}", i));
            }
            const std::string var_name = input.substr(i + 2, close - i - 2);
            const char* env_val = std::getenv(var_name.c_str());
            if (env_val) result += env_val;
            i = close + 1;
        } else {
            result += input[i++];
        }
    }
    return result;
}

void expand_env_vars_in_array(toml::array& arr);

void expand_env_vars_recursive(toml::table& tbl) {
    for (auto& [key, val] : tbl) {
        if (val.is_string()) {
            auto& s = *val.as_string();
            auto expanded = expand_env_vars(s.get());
            if (expanded != s.get()) {
                s = std::move(expanded);
            }
        } else if (val.is_table()) {
            expand_env_vars_recursive(*val.as_table());
        } else if (val.is_array()) {
            expand_env_vars_in_array(*val.as_array());
        }
    }
}

void expand_env_vars_in_array(toml::array& arr) {
    for (auto& elem : arr) {
        if (elem.is_string()) {
            auto& s = *elem.as_string();
            auto expanded = expand_env_vars(s.get());
            if (expanded != s.get()) {
                s = std::move(expanded);
            }
        } else if (elem.is_table()) {
            expand_env_vars_recursive(*elem.as_table());
        } else if (elem.is_array()) {
            expand_env_vars_in_array(*elem.as_array());
        }
    }
}

/**
 * @brief Deep-merge two toml::tables. Overlay wins for scalars.
 */
void merge_tables(toml::table& base, const toml::table& overlay) {
    for (const auto& [key, val] : overlay) {
        if (val.is_table() && base.contains(key) && base[key].is_table()) {
            merge_tables(*base[key].as_table(), *val.as_table());
        } else if (val.is_array() && base.contains(key) && base[key].is_array()) {
            auto& base_arr = *base[key].as_array();
            for (const auto& elem : *val.as_array()) {
                base_arr.push_back(elem);
            }
        } else {
            base.insert_or_assign(key, val);
        }
    }
}

/**
 * @brief Resolve include directives in a parsed TOML table.
 */
void resolve_includes(toml::table& root, const std::string& base_dir,
                      std::unordered_set<std::string>& visited, const int depth) {
    if (depth > 10) {
        throw std::runtime_error("Config include depth exceeds 10 — possible circular include");
    }
    auto inc_node = root["include"];
    if (!inc_node) return;

    std::vector<std::string> paths;
    if (inc_node.is_string()) {
        paths.emplace_back(inc_node.as_string()->get());
    } else if (inc_node.is_array()) {
        for (const auto& item : *inc_node.as_array()) {
            if (item.is_string()) {
                paths.emplace_back(item.as_string()->get());
            }
        }
    }
    root.erase("include");

    for (const auto& rel_path : paths) {
        namespace fs = std::filesystem;
        const std::string abs_path = fs::canonical(fs::path(base_dir) / rel_path).string();

        if (!visited.insert(abs_path).second) {
            throw std::runtime_error(
                std::format("Circular config include detected: {}", abs_path));
        }

        auto included = toml::parse_file(abs_path);
        const std::string inc_dir = fs::path(abs_path).parent_path().string();
        resolve_includes(included, inc_dir, visited, depth + 1);

        // Merge: included is base, root is overlay (main wins)
        merge_tables(included, root);
        root = std::move(included);
    }
}

toml::table parse_toml_string(const std::string& content) {
    auto result = toml::parse(content);
    expand_env_vars_recursive(result);
    return result;
}

toml::table parse_toml_file(const std::string& file_path) {
    auto result = toml::parse_file(file_path);

    namespace fs = std::filesystem;
    const std::string base_dir = fs::path(file_path).parent_path().string();
    std::unordered_set<std::string> visited;
    visited.insert(fs::canonical(file_path).string());
    resolve_includes(result, base_dir, visited, 0);

    expand_env_vars_recursive(result);
    return result;
}

// ---- Extraction helpers ----------------------------------------------------

std::vector<std::string> toml_string_array(const toml::table& tbl, const std::string_view key) {
    std::vector<std::string> result;
    if (const auto* arr = tbl[key].as_array()) {
        result.reserve(arr->size());
        for (const auto& elem : *arr) {
            if (const auto* s = elem.as_string()) {
                result.emplace_back(s->get());
            }
        }
    }
    return result;
}

std::optional<std::string> toml_optional_string(const toml::table& tbl, const std::string_view key) {
    if (const auto* v = tbl[key].as_string()) {
        return std::string(v->get());
    }
    return std::nullopt;
}

} // anonymous namespace

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
        {"copy",         StatementType::COPY},
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

// ---- Section extractors ----------------------------------------------------

ServerConfig ConfigLoader::extract_server(const toml::table& root) {
    ServerConfig cfg;
    const auto* server = root["server"].as_table();
    if (!server) return cfg;
    const auto& s = *server;

    cfg.host = s["host"].value_or("0.0.0.0"s);
    cfg.port = static_cast<uint16_t>(s["port"].value_or(8080));
    cfg.thread_pool_size = static_cast<size_t>(s["threads"].value_or(4));
    cfg.request_timeout = std::chrono::milliseconds(s["request_timeout_ms"].value_or(30000));
    cfg.admin_token = s["admin_token"].value_or(""s);
    cfg.max_sql_length = static_cast<size_t>(s["max_sql_length"].value_or(102400));

    if (const auto* tls = s["tls"].as_table()) {
        cfg.tls.enabled = (*tls)["enabled"].value_or(false);
        cfg.tls.cert_file = (*tls)["cert_file"].value_or(""s);
        cfg.tls.key_file = (*tls)["key_file"].value_or(""s);
        cfg.tls.ca_file = (*tls)["ca_file"].value_or(""s);
        cfg.tls.require_client_cert = (*tls)["require_client_cert"].value_or(false);
    }

    cfg.shutdown_timeout_ms = static_cast<uint32_t>(s["shutdown_timeout_ms"].value_or(30000));
    cfg.compression_enabled = s["compression_enabled"].value_or(false);
    cfg.compression_min_size_bytes = static_cast<size_t>(s["compression_min_size_bytes"].value_or(1024));

    if (const auto* proxies = s["trusted_proxies"].as_array()) {
        for (const auto& p : *proxies) {
            if (auto v = p.value<std::string>()) {
                cfg.trusted_proxies.push_back(*v);
            }
        }
    }

    return cfg;
}

LoggingConfig ConfigLoader::extract_logging(const toml::table& root) {
    LoggingConfig cfg;
    const auto* logging = root["logging"].as_table();
    if (!logging) return cfg;
    const auto& l = *logging;

    cfg.level = l["level"].value_or("info"s);
    cfg.file = l["file"].value_or(""s);
    cfg.async_logging = l["async"].value_or(true);
    return cfg;
}

std::vector<DatabaseConfig> ConfigLoader::extract_databases(const toml::table& root) {
    std::vector<DatabaseConfig> result;
    const auto* arr = root["databases"].as_array();
    if (!arr) return result;
    result.reserve(arr->size());

    for (const auto& elem : *arr) {
        const auto* db = elem.as_table();
        if (!db) continue;

        DatabaseConfig cfg;
        cfg.name = (*db)["name"].value_or("default"s);
        cfg.type_str = (*db)["type"].value_or("postgresql"s);
        cfg.connection_string = (*db)["connection_string"].value_or(""s);
        cfg.min_connections = static_cast<size_t>((*db)["min_connections"].value_or(2));
        cfg.max_connections = static_cast<size_t>((*db)["max_connections"].value_or(10));
        cfg.connection_timeout = std::chrono::milliseconds((*db)["connection_timeout_ms"].value_or(5000));
        cfg.query_timeout = std::chrono::milliseconds((*db)["query_timeout_ms"].value_or(30000));
        cfg.health_check_query = (*db)["health_check_query"].value_or("SELECT 1"s);
        cfg.health_check_interval_seconds = (*db)["health_check_interval_seconds"].value_or(10);
        cfg.idle_timeout_seconds = (*db)["idle_timeout_seconds"].value_or(300);
        cfg.pool_acquire_timeout_ms = (*db)["pool_acquire_timeout_ms"].value_or(5000);
        cfg.max_result_rows = static_cast<size_t>((*db)["max_result_rows"].value_or(10000));
        cfg.region = (*db)["region"].value_or(""s);

        if (const auto* replicas = (*db)["replicas"].as_array()) {
            cfg.replicas.reserve(replicas->size());
            for (const auto& r_elem : *replicas) {
                const auto* r = r_elem.as_table();
                if (!r) continue;
                ReplicaConfig replica;
                replica.connection_string = (*r)["connection_string"].value_or(""s);
                replica.min_connections = static_cast<size_t>((*r)["min_connections"].value_or(2));
                replica.max_connections = static_cast<size_t>((*r)["max_connections"].value_or(5));
                replica.connection_timeout = std::chrono::milliseconds((*r)["connection_timeout_ms"].value_or(5000));
                replica.health_check_query = (*r)["health_check_query"].value_or("SELECT 1"s);
                replica.weight = (*r)["weight"].value_or(1);
                if (!replica.connection_string.empty()) {
                    cfg.replicas.emplace_back(std::move(replica));
                }
            }
        }

        result.emplace_back(std::move(cfg));
    }
    return result;
}

std::unordered_map<std::string, UserInfo> ConfigLoader::extract_users(const toml::table& root) {
    std::unordered_map<std::string, UserInfo> result;
    const auto* arr = root["users"].as_array();
    if (!arr) return result;

    for (const auto& elem : *arr) {
        const auto* u = elem.as_table();
        if (!u) continue;

        std::string name = (*u)["name"].value_or(""s);
        if (name.empty()) continue;

        auto roles = toml_string_array(*u, "roles");
        std::string api_key = (*u)["api_key"].value_or(""s);

        UserInfo info(std::move(name), std::move(roles), std::move(api_key));
        info.allowed_ips = toml_string_array(*u, "allowed_ips");

        std::string default_db = (*u)["default_database"].value_or(""s);
        if (!default_db.empty()) {
            info.default_database = std::move(default_db);
        }

        if (const auto* attrs = (*u)["attributes"].as_table()) {
            for (const auto& [k, v] : *attrs) {
                if (v.is_string()) {
                    info.attributes[std::string(k)] = v.as_string()->get();
                }
            }
        }

        result.emplace(info.name, std::move(info));
    }
    return result;
}

std::vector<Policy> ConfigLoader::extract_policies(const toml::table& root) {
    std::vector<Policy> result;
    const auto* arr = root["policies"].as_array();
    if (!arr) return result;
    result.reserve(arr->size());

    for (const auto& elem : *arr) {
        const auto* p = elem.as_table();
        if (!p) continue;

        Policy policy;
        policy.name = (*p)["name"].value_or(""s);
        if (policy.name.empty()) continue;

        policy.priority = (*p)["priority"].value_or(0);

        const std::string action_str = (*p)["action"].value_or("BLOCK"s);
        const auto action = parse_action(action_str);
        policy.action = action.value_or(Decision::BLOCK);

        for (const auto& user : toml_string_array(*p, "users")) {
            policy.users.insert(user);
        }
        for (const auto& role : toml_string_array(*p, "roles")) {
            policy.roles.insert(role);
        }
        for (const auto& role : toml_string_array(*p, "exclude_roles")) {
            policy.exclude_roles.insert(role);
        }

        for (const auto& stmt_str : toml_string_array(*p, "statement_types")) {
            const auto stmt_type = parse_statement_type(stmt_str);
            if (stmt_type.has_value()) {
                policy.scope.operations.insert(*stmt_type);
            }
        }

        policy.scope.database = toml_optional_string(*p, "database");
        policy.scope.schema = toml_optional_string(*p, "schema");
        policy.scope.table = toml_optional_string(*p, "table");
        policy.scope.columns = toml_string_array(*p, "columns");

        if (const auto* masking_node = (*p)["masking_action"].as_string()) {
            static const std::unordered_map<std::string, MaskingAction> masking_lookup = {
                {"none", MaskingAction::NONE},
                {"redact", MaskingAction::REDACT},
                {"partial", MaskingAction::PARTIAL},
                {"hash", MaskingAction::HASH},
                {"nullify", MaskingAction::NULLIFY},
            };
            const std::string masking_str = utils::to_lower(masking_node->get());
            const auto mit = masking_lookup.find(masking_str);
            if (mit != masking_lookup.end()) {
                policy.masking_action = mit->second;
            }
        }
        policy.masking_prefix_len = (*p)["masking_prefix_len"].value_or(3);
        policy.masking_suffix_len = (*p)["masking_suffix_len"].value_or(3);

        policy.reason = (*p)["reason"].value_or(""s);
        policy.shadow = (*p)["shadow"].value_or(false);

        result.emplace_back(std::move(policy));
    }

    return result;
}

RateLimitingConfig ConfigLoader::extract_rate_limiting(const toml::table& root) {
    RateLimitingConfig cfg;
    const auto* rl_node = root["rate_limiting"].as_table();
    if (!rl_node) return cfg;
    const auto& rl = *rl_node;

    cfg.enabled = rl["enabled"].value_or(true);

    if (const auto* g = rl["global"].as_table()) {
        cfg.global_tokens_per_second = static_cast<uint32_t>((*g)["tokens_per_second"].value_or(50000));
        cfg.global_burst_capacity = static_cast<uint32_t>((*g)["burst_capacity"].value_or(10000));
    }

    if (const auto* arr = rl["per_user"].as_array()) {
        cfg.per_user.reserve(arr->size());
        for (const auto& elem : *arr) {
            const auto* u = elem.as_table();
            if (!u) continue;
            PerUserRateLimit limit;
            limit.user = (*u)["user"].value_or(""s);
            limit.tokens_per_second = static_cast<uint32_t>((*u)["tokens_per_second"].value_or(100));
            limit.burst_capacity = static_cast<uint32_t>((*u)["burst_capacity"].value_or(20));
            if (!limit.user.empty()) {
                cfg.per_user.emplace_back(std::move(limit));
            }
        }
    }

    if (const auto* d = rl["per_user_default"].as_table()) {
        cfg.per_user_default_tokens_per_second = static_cast<uint32_t>((*d)["tokens_per_second"].value_or(100));
        cfg.per_user_default_burst_capacity = static_cast<uint32_t>((*d)["burst_capacity"].value_or(20));
    }

    if (const auto* arr = rl["per_database"].as_array()) {
        cfg.per_database.reserve(arr->size());
        for (const auto& elem : *arr) {
            const auto* db_tbl = elem.as_table();
            if (!db_tbl) continue;
            PerDatabaseRateLimit limit;
            limit.database = (*db_tbl)["database"].value_or(""s);
            limit.tokens_per_second = static_cast<uint32_t>((*db_tbl)["tokens_per_second"].value_or(30000));
            limit.burst_capacity = static_cast<uint32_t>((*db_tbl)["burst_capacity"].value_or(5000));
            if (!limit.database.empty()) {
                cfg.per_database.emplace_back(std::move(limit));
            }
        }
    }

    if (const auto* arr = rl["per_user_per_database"].as_array()) {
        cfg.per_user_per_database.reserve(arr->size());
        for (const auto& elem : *arr) {
            const auto* upd = elem.as_table();
            if (!upd) continue;
            PerUserPerDatabaseRateLimit limit;
            limit.user = (*upd)["user"].value_or(""s);
            limit.database = (*upd)["database"].value_or(""s);
            limit.tokens_per_second = static_cast<uint32_t>((*upd)["tokens_per_second"].value_or(100));
            limit.burst_capacity = static_cast<uint32_t>((*upd)["burst_capacity"].value_or(20));
            if (!limit.user.empty() && !limit.database.empty()) {
                cfg.per_user_per_database.emplace_back(std::move(limit));
            }
        }
    }

    if (const auto* q = rl["queue"].as_table()) {
        cfg.queue_enabled = (*q)["enabled"].value_or(false);
        cfg.queue_timeout_ms = static_cast<uint32_t>((*q)["timeout_ms"].value_or(5000));
        cfg.max_queue_depth = static_cast<uint32_t>((*q)["max_depth"].value_or(1000));
    }

    return cfg;
}

CacheConfig ConfigLoader::extract_cache(const toml::table& root) {
    CacheConfig cfg;
    const auto* cache = root["cache"].as_table();
    if (!cache) return cfg;
    const auto& c = *cache;

    cfg.max_entries = static_cast<size_t>(c["max_entries"].value_or(10000));
    cfg.num_shards = static_cast<size_t>(c["num_shards"].value_or(16));
    cfg.ttl = std::chrono::seconds(c["ttl_seconds"].value_or(300));
    return cfg;
}

AuditConfig ConfigLoader::extract_audit(const toml::table& root) {
    AuditConfig cfg;
    const auto* audit = root["audit"].as_table();
    if (!audit) return cfg;
    const auto& a = *audit;

    cfg.async_mode = a["async_mode"].value_or(true);
    cfg.ring_buffer_size = static_cast<size_t>(a["ring_buffer_size"].value_or(65536));
    cfg.batch_flush_interval = std::chrono::milliseconds(a["flush_interval_ms"].value_or(1000));
    cfg.max_batch_size = static_cast<size_t>(a["max_batch_size"].value_or(1000));
    cfg.fsync_interval_batches = a["fsync_interval_batches"].value_or(10);

    if (const auto* f = a["file"].as_table()) {
        cfg.output_file = (*f)["output_file"].value_or("audit.jsonl"s);
    }

    if (const auto* db_tbl = a["database"].as_table()) {
        const int db_flush = (*db_tbl)["flush_interval_ms"].value_or(0);
        if (db_flush > 0) {
            cfg.batch_flush_interval = std::chrono::milliseconds(db_flush);
        }
    }

    if (const auto* r = a["rotation"].as_table()) {
        cfg.rotation_max_file_size_mb = static_cast<size_t>((*r)["max_file_size_mb"].value_or(100));
        cfg.rotation_max_files = (*r)["max_files"].value_or(10);
        cfg.rotation_interval_hours = (*r)["interval_hours"].value_or(24);
        cfg.rotation_time_based = (*r)["time_based"].value_or(true);
        cfg.rotation_size_based = (*r)["size_based"].value_or(true);
    }

    if (const auto* w = a["webhook"].as_table()) {
        cfg.webhook_enabled = (*w)["enabled"].value_or(false);
        cfg.webhook_url = (*w)["url"].value_or(""s);
        cfg.webhook_auth_header = (*w)["auth_header"].value_or(""s);
        cfg.webhook_timeout_ms = (*w)["timeout_ms"].value_or(5000);
        cfg.webhook_max_retries = (*w)["max_retries"].value_or(3);
        cfg.webhook_batch_size = (*w)["batch_size"].value_or(100);
    }

    if (const auto* sy = a["syslog"].as_table()) {
        cfg.syslog_enabled = (*sy)["enabled"].value_or(false);
        cfg.syslog_ident = (*sy)["ident"].value_or("sql-proxy"s);
    }

    if (const auto* ka = a["kafka"].as_table()) {
        cfg.kafka_enabled = (*ka)["enabled"].value_or(false);
        cfg.kafka_brokers = (*ka)["brokers"].value_or("localhost:9092"s);
        cfg.kafka_topic = (*ka)["topic"].value_or("sql-proxy-audit"s);
    }

    if (const auto* ig = a["integrity"].as_table()) {
        cfg.integrity_enabled = (*ig)["enabled"].value_or(true);
        cfg.integrity_algorithm = (*ig)["algorithm"].value_or("sha256"s);
    }

    return cfg;
}

std::vector<ClassifierConfig> ConfigLoader::extract_classifiers(const toml::table& root) {
    std::vector<ClassifierConfig> result;
    const auto* arr = root["classifiers"].as_array();
    if (!arr) return result;
    result.reserve(arr->size());

    for (const auto& elem : *arr) {
        const auto* c = elem.as_table();
        if (!c) continue;

        ClassifierConfig cfg;
        cfg.type = (*c)["type"].value_or(""s);
        cfg.strategy = (*c)["strategy"].value_or(""s);
        cfg.patterns = toml_string_array(*c, "patterns");
        cfg.data_validation_regex = (*c)["data_validation_regex"].value_or(""s);
        cfg.sample_size = (*c)["sample_size"].value_or(0);
        cfg.confidence_threshold = (*c)["confidence_threshold"].value_or(0.0);

        if (!cfg.type.empty()) {
            result.emplace_back(std::move(cfg));
        }
    }

    return result;
}

CircuitBreakerConfig ConfigLoader::extract_circuit_breaker(const toml::table& root) {
    CircuitBreakerConfig cfg;
    const auto* cb = root["circuit_breaker"].as_table();
    if (!cb) return cfg;

    cfg.enabled = (*cb)["enabled"].value_or(true);
    cfg.failure_threshold = (*cb)["failure_threshold"].value_or(15);
    cfg.success_threshold = (*cb)["success_threshold"].value_or(5);
    cfg.timeout_ms = (*cb)["timeout_ms"].value_or(5000);
    cfg.half_open_max_calls = (*cb)["half_open_max_calls"].value_or(5);
    return cfg;
}

AllocatorConfig ConfigLoader::extract_allocator(const toml::table& root) {
    AllocatorConfig cfg;
    const auto* a = root["allocator"].as_table();
    if (!a) return cfg;

    cfg.enabled = (*a)["enabled"].value_or(true);
    cfg.initial_size_bytes = static_cast<size_t>((*a)["initial_size_bytes"].value_or(1024));
    cfg.max_size_bytes = static_cast<size_t>((*a)["max_size_bytes"].value_or(65536));
    return cfg;
}

MetricsConfig ConfigLoader::extract_metrics(const toml::table& root) {
    MetricsConfig cfg;
    const auto* m = root["metrics"].as_table();
    if (!m) return cfg;

    cfg.enabled = (*m)["enabled"].value_or(true);
    cfg.endpoint = (*m)["endpoint"].value_or("/metrics"s);
    cfg.export_interval_ms = (*m)["export_interval_ms"].value_or(5000);
    return cfg;
}

ConfigWatcherConfig ConfigLoader::extract_config_watcher(const toml::table& root) {
    ConfigWatcherConfig cfg;
    const auto* cw = root["config_watcher"].as_table();
    if (!cw) return cfg;

    cfg.enabled = (*cw)["enabled"].value_or(true);
    cfg.poll_interval_seconds = (*cw)["poll_interval_seconds"].value_or(5);
    return cfg;
}

SecurityConfig ConfigLoader::extract_security(const toml::table& root) {
    SecurityConfig cfg;
    const auto* sec = root["security"].as_table();
    if (!sec) return cfg;
    const auto& s = *sec;

    cfg.injection_detection_enabled = s["injection_detection"].value_or(true);
    cfg.anomaly_detection_enabled = s["anomaly_detection"].value_or(true);
    cfg.lineage_tracking_enabled = s["lineage_tracking"].value_or(true);

    if (const auto* fw = s["firewall"].as_table()) {
        cfg.firewall_enabled = (*fw)["enabled"].value_or(false);
        cfg.firewall_mode = (*fw)["mode"].value_or("disabled"s);
    }

    if (const auto* bf = s["brute_force"].as_table()) {
        cfg.brute_force_enabled = (*bf)["enabled"].value_or(false);
        cfg.brute_force_max_attempts = static_cast<uint32_t>((*bf)["max_attempts"].value_or(5));
        cfg.brute_force_window_seconds = static_cast<uint32_t>((*bf)["window_seconds"].value_or(60));
        cfg.brute_force_lockout_seconds = static_cast<uint32_t>((*bf)["lockout_seconds"].value_or(300));
        cfg.brute_force_max_lockout_seconds = static_cast<uint32_t>((*bf)["max_lockout_seconds"].value_or(3600));
    }
    return cfg;
}

EncryptionConfig ConfigLoader::extract_encryption(const toml::table& root) {
    EncryptionConfig cfg;
    const auto* enc = root["encryption"].as_table();
    if (!enc) return cfg;
    const auto& e = *enc;

    cfg.enabled = e["enabled"].value_or(false);
    cfg.key_file = e["key_file"].value_or("config/encryption_keys.json"s);

    if (const auto* arr = e["columns"].as_array()) {
        cfg.columns.reserve(arr->size());
        for (const auto& elem : *arr) {
            const auto* c = elem.as_table();
            if (!c) continue;
            EncryptionColumnConfigEntry entry;
            entry.database = (*c)["database"].value_or(""s);
            entry.table = (*c)["table"].value_or(""s);
            entry.column = (*c)["column"].value_or(""s);
            if (!entry.column.empty()) {
                cfg.columns.emplace_back(std::move(entry));
            }
        }
    }

    if (const auto* km = e["key_manager"].as_table()) {
        cfg.key_manager_provider = (*km)["provider"].value_or("local"s);
        cfg.vault_addr = (*km)["vault_addr"].value_or(""s);
        cfg.vault_token = (*km)["vault_token"].value_or(""s);
        cfg.vault_key_name = (*km)["vault_key_name"].value_or("sql-proxy"s);
        cfg.vault_mount = (*km)["vault_mount"].value_or("transit"s);
        cfg.vault_cache_ttl_seconds = (*km)["vault_cache_ttl_seconds"].value_or(300);
        cfg.env_key_var = (*km)["env_key_var"].value_or("ENCRYPTION_KEY"s);
    }

    return cfg;
}

// ---- RLS & Rewrite Rule extractors -----------------------------------------

namespace {

std::vector<RlsRule> extract_rls_rules(const toml::table& root) {
    std::vector<RlsRule> result;
    const auto* arr = root["row_level_security"].as_array();
    if (!arr) return result;
    result.reserve(arr->size());

    for (const auto& elem : *arr) {
        const auto* r = elem.as_table();
        if (!r) continue;

        RlsRule rule;
        rule.name = (*r)["name"].value_or(""s);
        if (rule.name.empty()) continue;
        rule.database = toml_optional_string(*r, "database");
        rule.table = toml_optional_string(*r, "table");
        rule.condition = (*r)["condition"].value_or(""s);
        rule.users = toml_string_array(*r, "users");
        rule.roles = toml_string_array(*r, "roles");
        if (!rule.condition.empty()) {
            result.emplace_back(std::move(rule));
        }
    }
    return result;
}

std::vector<RewriteRule> extract_rewrite_rules(const toml::table& root) {
    std::vector<RewriteRule> result;
    const auto* arr = root["rewrite_rules"].as_array();
    if (!arr) return result;
    result.reserve(arr->size());

    for (const auto& elem : *arr) {
        const auto* r = elem.as_table();
        if (!r) continue;

        RewriteRule rule;
        rule.name = (*r)["name"].value_or(""s);
        if (rule.name.empty()) continue;
        rule.type = (*r)["type"].value_or(""s);
        rule.limit_value = (*r)["limit_value"].value_or(1000);
        rule.users = toml_string_array(*r, "users");
        rule.roles = toml_string_array(*r, "roles");
        if (!rule.type.empty()) {
            result.emplace_back(std::move(rule));
        }
    }
    return result;
}

} // anonymous namespace

// ---- Tier 5 extractors -----------------------------------------------------

TenantConfigEntry ConfigLoader::extract_tenants(const toml::table& root) {
    TenantConfigEntry cfg;
    const auto* t = root["tenants"].as_table();
    if (!t) return cfg;

    cfg.enabled = (*t)["enabled"].value_or(false);
    cfg.default_tenant = (*t)["default_tenant"].value_or("default"s);
    cfg.header_name = (*t)["header_name"].value_or("X-Tenant-Id"s);
    return cfg;
}

std::vector<PluginConfigEntry> ConfigLoader::extract_plugins(const toml::table& root) {
    std::vector<PluginConfigEntry> result;
    const auto* arr = root["plugins"].as_array();
    if (!arr) return result;
    result.reserve(arr->size());

    for (const auto& elem : *arr) {
        const auto* p = elem.as_table();
        if (!p) continue;
        PluginConfigEntry entry;
        entry.path = (*p)["path"].value_or(""s);
        entry.type = (*p)["type"].value_or(""s);
        entry.config = (*p)["config"].value_or(""s);
        if (!entry.path.empty() && !entry.type.empty()) {
            result.emplace_back(std::move(entry));
        }
    }
    return result;
}

SchemaManagementConfigEntry ConfigLoader::extract_schema_management(const toml::table& root) {
    SchemaManagementConfigEntry cfg;
    const auto* s = root["schema_management"].as_table();
    if (!s) return cfg;

    cfg.enabled = (*s)["enabled"].value_or(false);
    cfg.require_approval = (*s)["require_approval"].value_or(false);
    cfg.max_history_entries = static_cast<size_t>((*s)["max_history_entries"].value_or(1000));
    return cfg;
}

WireProtocolConfigEntry ConfigLoader::extract_wire_protocol(const toml::table& root) {
    WireProtocolConfigEntry cfg;
    const auto* w = root["wire_protocol"].as_table();
    if (!w) return cfg;

    cfg.enabled = (*w)["enabled"].value_or(false);
    cfg.host = (*w)["host"].value_or("0.0.0.0"s);
    cfg.port = static_cast<uint16_t>((*w)["port"].value_or(5433));
    cfg.max_connections = static_cast<uint32_t>((*w)["max_connections"].value_or(100));
    cfg.thread_pool_size = static_cast<uint32_t>((*w)["thread_pool_size"].value_or(4));
    cfg.require_password = (*w)["require_password"].value_or(false);
    cfg.prefer_scram = (*w)["prefer_scram"].value_or(false);
    cfg.scram_iterations = static_cast<uint32_t>((*w)["scram_iterations"].value_or(4096));

    // TLS sub-section
    const auto* tls = (*w)["tls"].as_table();
    if (tls) {
        cfg.tls.enabled = (*tls)["enabled"].value_or(false);
        cfg.tls.cert_file = (*tls)["cert_file"].value_or(""s);
        cfg.tls.key_file = (*tls)["key_file"].value_or(""s);
        cfg.tls.ca_file = (*tls)["ca_file"].value_or(""s);
        cfg.tls.require_client_cert = (*tls)["require_client_cert"].value_or(false);
    }

    return cfg;
}

GraphQLConfigEntry ConfigLoader::extract_graphql(const toml::table& root) {
    GraphQLConfigEntry cfg;
    const auto* g = root["graphql"].as_table();
    if (!g) return cfg;

    cfg.enabled = (*g)["enabled"].value_or(false);
    cfg.endpoint = (*g)["endpoint"].value_or("/api/v1/graphql"s);
    cfg.max_query_depth = static_cast<uint32_t>((*g)["max_query_depth"].value_or(5));
    cfg.mutations_enabled = (*g)["mutations_enabled"].value_or(false);
    return cfg;
}

BinaryRpcConfigEntry ConfigLoader::extract_binary_rpc(const toml::table& root) {
    BinaryRpcConfigEntry cfg;
    const auto* b = root["binary_rpc"].as_table();
    if (!b) return cfg;

    cfg.enabled = (*b)["enabled"].value_or(false);
    cfg.host = (*b)["host"].value_or("0.0.0.0"s);
    cfg.port = static_cast<uint16_t>((*b)["port"].value_or(9090));
    cfg.max_connections = static_cast<uint32_t>((*b)["max_connections"].value_or(50));
    return cfg;
}

AlertingConfig ConfigLoader::extract_alerting(const toml::table& root) {
    AlertingConfig cfg;
    const auto* alert = root["alerting"].as_table();
    if (!alert) return cfg;
    const auto& a = *alert;

    cfg.enabled = a["enabled"].value_or(false);
    cfg.evaluation_interval_seconds = a["evaluation_interval_seconds"].value_or(10);
    cfg.alert_log_file = a["alert_log_file"].value_or("alerts.jsonl"s);

    if (const auto* w = a["webhook"].as_table()) {
        cfg.webhook.enabled = (*w)["enabled"].value_or(false);
        cfg.webhook.url = (*w)["url"].value_or(""s);
        cfg.webhook.auth_header = (*w)["auth_header"].value_or(""s);
    }

    if (const auto* rules_arr = a["rules"].as_array()) {
        for (const auto& elem : *rules_arr) {
            const auto* r = elem.as_table();
            if (!r) continue;
            AlertRule rule;
            rule.name = (*r)["name"].value_or(""s);
            rule.condition = parse_alert_condition((*r)["condition"].value_or("custom_metric"s));
            rule.threshold = (*r)["threshold"].value_or(0.0);
            rule.window = std::chrono::seconds((*r)["window_seconds"].value_or(60));
            rule.cooldown = std::chrono::seconds((*r)["cooldown_seconds"].value_or(300));
            rule.severity = (*r)["severity"].value_or("warning"s);
            rule.enabled = (*r)["enabled"].value_or(true);
            cfg.rules.emplace_back(std::move(rule));
        }
    }

    return cfg;
}

AuthConfig ConfigLoader::extract_auth(const toml::table& root) {
    AuthConfig cfg;
    const auto* auth = root["auth"].as_table();
    if (!auth) return cfg;
    const auto& a = *auth;

    cfg.provider = a["provider"].value_or("api_key"s);

    if (const auto* j = a["jwt"].as_table()) {
        cfg.jwt_issuer = (*j)["issuer"].value_or(""s);
        cfg.jwt_audience = (*j)["audience"].value_or(""s);
        cfg.jwt_secret = (*j)["secret"].value_or(""s);
        cfg.jwt_roles_claim = (*j)["roles_claim"].value_or("roles"s);
    }

    if (const auto* l = a["ldap"].as_table()) {
        cfg.ldap_url = (*l)["url"].value_or(""s);
        cfg.ldap_base_dn = (*l)["base_dn"].value_or(""s);
        cfg.ldap_bind_dn = (*l)["bind_dn"].value_or(""s);
        cfg.ldap_bind_password = (*l)["bind_password"].value_or(""s);
        cfg.ldap_user_filter = (*l)["user_filter"].value_or("(uid={})"s);
        cfg.ldap_group_attribute = (*l)["group_attribute"].value_or("memberOf"s);
    }

    if (const auto* o = a["oidc"].as_table()) {
        cfg.oidc_issuer = (*o)["issuer"].value_or(""s);
        cfg.oidc_audience = (*o)["audience"].value_or(""s);
        cfg.oidc_jwks_uri = (*o)["jwks_uri"].value_or(""s);
        cfg.oidc_roles_claim = (*o)["roles_claim"].value_or("roles"s);
        cfg.oidc_user_claim = (*o)["user_claim"].value_or("sub"s);
        cfg.oidc_jwks_cache_seconds = static_cast<uint32_t>((*o)["jwks_cache_seconds"].value_or(3600));
    }

    return cfg;
}

// ---- Tier B extractors -----------------------------------------------------

ProxyConfig::AuditSamplingConfig ConfigLoader::extract_audit_sampling(const toml::table& root) {
    ProxyConfig::AuditSamplingConfig cfg;
    const auto* audit = root["audit"].as_table();
    if (!audit) return cfg;
    const auto* sampling = (*audit)["sampling"].as_table();
    if (!sampling) return cfg;
    const auto& s = *sampling;

    cfg.enabled = s["enabled"].value_or(false);
    cfg.default_sample_rate = s["default_sample_rate"].value_or(1.0);
    cfg.select_sample_rate = s["select_sample_rate"].value_or(1.0);
    cfg.always_log_blocked = s["always_log_blocked"].value_or(true);
    cfg.always_log_writes = s["always_log_writes"].value_or(true);
    cfg.always_log_errors = s["always_log_errors"].value_or(true);
    cfg.deterministic = s["deterministic"].value_or(true);
    return cfg;
}

ProxyConfig::ResultCacheConfig ConfigLoader::extract_result_cache(const toml::table& root) {
    ProxyConfig::ResultCacheConfig cfg;
    const auto* rc = root["result_cache"].as_table();
    if (!rc) return cfg;

    cfg.enabled = (*rc)["enabled"].value_or(false);
    cfg.max_entries = static_cast<size_t>((*rc)["max_entries"].value_or(5000));
    cfg.num_shards = static_cast<size_t>((*rc)["num_shards"].value_or(16));
    cfg.ttl_seconds = (*rc)["ttl_seconds"].value_or(60);
    cfg.max_result_size_bytes = static_cast<size_t>((*rc)["max_result_size_bytes"].value_or(1048576));
    return cfg;
}

// ---- Tier C/F/G extractors -------------------------------------------------

ProxyConfig::SlowQueryConfig ConfigLoader::extract_slow_query(const toml::table& root) {
    ProxyConfig::SlowQueryConfig cfg;
    const auto* sq = root["slow_query"].as_table();
    if (!sq) return cfg;

    cfg.enabled = (*sq)["enabled"].value_or(false);
    cfg.threshold_ms = static_cast<uint32_t>((*sq)["threshold_ms"].value_or(500));
    cfg.max_entries = static_cast<size_t>((*sq)["max_entries"].value_or(1000));
    return cfg;
}

ProxyConfig::QueryCostConfig ConfigLoader::extract_query_cost(const toml::table& root) {
    ProxyConfig::QueryCostConfig cfg;
    const auto* qc = root["query_cost"].as_table();
    if (!qc) return cfg;

    cfg.enabled = (*qc)["enabled"].value_or(false);
    cfg.max_cost = (*qc)["max_cost"].value_or(100000.0);
    cfg.max_estimated_rows = static_cast<uint64_t>((*qc)["max_estimated_rows"].value_or(1000000));
    cfg.log_estimates = (*qc)["log_estimates"].value_or(false);
    return cfg;
}

ProxyConfig::SchemaDriftConfig ConfigLoader::extract_schema_drift(const toml::table& root) {
    ProxyConfig::SchemaDriftConfig cfg;
    const auto* sd = root["schema_drift"].as_table();
    if (!sd) return cfg;

    cfg.enabled = (*sd)["enabled"].value_or(false);
    cfg.check_interval_seconds = (*sd)["check_interval_seconds"].value_or(600);
    cfg.database = (*sd)["database"].value_or("testdb"s);
    cfg.schema_name = (*sd)["schema_name"].value_or("public"s);
    return cfg;
}

ProxyConfig::RetryConfig ConfigLoader::extract_retry(const toml::table& root) {
    ProxyConfig::RetryConfig cfg;
    const auto* rt = root["retry"].as_table();
    if (!rt) return cfg;

    cfg.enabled = (*rt)["enabled"].value_or(false);
    cfg.max_retries = (*rt)["max_retries"].value_or(1);
    cfg.initial_backoff_ms = (*rt)["initial_backoff_ms"].value_or(100);
    cfg.max_backoff_ms = (*rt)["max_backoff_ms"].value_or(2000);
    return cfg;
}

ProxyConfig::RequestTimeoutConfig ConfigLoader::extract_request_timeout(const toml::table& root) {
    ProxyConfig::RequestTimeoutConfig cfg;
    const auto* rt = root["request_timeout"].as_table();
    if (!rt) return cfg;

    cfg.enabled = (*rt)["enabled"].value_or(true);
    cfg.timeout_ms = static_cast<uint32_t>((*rt)["timeout_ms"].value_or(30000));
    return cfg;
}

ProxyConfig::AuditEncryptionConfig ConfigLoader::extract_audit_encryption(const toml::table& root) {
    ProxyConfig::AuditEncryptionConfig cfg;

    if (const auto* ae = root["audit_encryption"].as_table()) {
        cfg.enabled = (*ae)["enabled"].value_or(false);
        cfg.key_id = (*ae)["key_id"].value_or("audit-key-1"s);
    } else if (const auto* audit = root["audit"].as_table()) {
        if (const auto* enc = (*audit)["encryption"].as_table()) {
            cfg.enabled = (*enc)["enabled"].value_or(false);
            cfg.key_id = (*enc)["key_id"].value_or("audit-key-1"s);
        }
    }
    return cfg;
}

ProxyConfig::TracingConfig ConfigLoader::extract_tracing(const toml::table& root) {
    ProxyConfig::TracingConfig cfg;
    const auto* t = root["tracing"].as_table();
    if (!t) return cfg;

    cfg.spans_enabled = (*t)["spans_enabled"].value_or(false);
    return cfg;
}

ProxyConfig::AdaptiveRateLimitingConfig ConfigLoader::extract_adaptive_rate_limiting(const toml::table& root) {
    ProxyConfig::AdaptiveRateLimitingConfig cfg;
    const auto* arl = root["adaptive_rate_limiting"].as_table();
    if (!arl) return cfg;

    cfg.enabled = (*arl)["enabled"].value_or(false);
    cfg.adjustment_interval_seconds = static_cast<uint32_t>((*arl)["adjustment_interval_seconds"].value_or(10));
    cfg.latency_target_ms = static_cast<uint32_t>((*arl)["latency_target_ms"].value_or(50));
    cfg.throttle_threshold_ms = static_cast<uint32_t>((*arl)["throttle_threshold_ms"].value_or(200));
    return cfg;
}

ProxyConfig::PriorityConfig ConfigLoader::extract_priority(const toml::table& root) {
    ProxyConfig::PriorityConfig cfg;
    const auto* p = root["priority"].as_table();
    if (!p) return cfg;

    cfg.enabled = (*p)["enabled"].value_or(false);
    return cfg;
}

ProxyConfig::DataResidencyConfig ConfigLoader::extract_data_residency(const toml::table& root) {
    ProxyConfig::DataResidencyConfig cfg;
    const auto* sec = root["data_residency"].as_table();
    if (!sec) return cfg;
    cfg.enabled = (*sec)["enabled"].value_or(false);
    return cfg;
}

ProxyConfig::ColumnVersioningConfig ConfigLoader::extract_column_versioning(const toml::table& root) {
    ProxyConfig::ColumnVersioningConfig cfg;
    const auto* sec = root["column_versioning"].as_table();
    if (!sec) return cfg;
    cfg.enabled = (*sec)["enabled"].value_or(false);
    cfg.max_events = static_cast<size_t>((*sec)["max_events"].value_or(10000));
    return cfg;
}

ProxyConfig::SyntheticDataConfig ConfigLoader::extract_synthetic_data(const toml::table& root) {
    ProxyConfig::SyntheticDataConfig cfg;
    const auto* sec = root["synthetic_data"].as_table();
    if (!sec) return cfg;
    cfg.enabled = (*sec)["enabled"].value_or(false);
    cfg.max_rows = static_cast<size_t>((*sec)["max_rows"].value_or(10000));
    return cfg;
}

ProxyConfig::CostBasedRewritingConfig ConfigLoader::extract_cost_based_rewriting(const toml::table& root) {
    ProxyConfig::CostBasedRewritingConfig cfg;
    const auto* sec = root["cost_based_rewriting"].as_table();
    if (!sec) return cfg;
    cfg.enabled = (*sec)["enabled"].value_or(false);
    cfg.cost_threshold = (*sec)["cost_threshold"].value_or(50000.0);
    cfg.max_columns_for_star = static_cast<size_t>((*sec)["max_columns_for_star"].value_or(20));
    return cfg;
}

ProxyConfig::DistributedRateLimitingConfig ConfigLoader::extract_distributed_rate_limiting(const toml::table& root) {
    ProxyConfig::DistributedRateLimitingConfig cfg;
    const auto* sec = root["distributed_rate_limiting"].as_table();
    if (!sec) return cfg;
    cfg.enabled = (*sec)["enabled"].value_or(false);
    cfg.node_id = (*sec)["node_id"].value_or(std::string("node-1"));
    cfg.cluster_size = static_cast<uint32_t>((*sec)["cluster_size"].value_or(1));
    cfg.sync_interval_ms = static_cast<uint32_t>((*sec)["sync_interval_ms"].value_or(5000));
    cfg.backend_type = (*sec)["backend_type"].value_or(std::string("memory"));
    return cfg;
}

ProxyConfig::WebSocketConfig ConfigLoader::extract_websocket(const toml::table& root) {
    ProxyConfig::WebSocketConfig cfg;
    const auto* sec = root["websocket"].as_table();
    if (!sec) return cfg;
    cfg.enabled = (*sec)["enabled"].value_or(false);
    cfg.endpoint = (*sec)["endpoint"].value_or(std::string("/api/v1/stream"));
    cfg.max_connections = static_cast<uint32_t>((*sec)["max_connections"].value_or(100));
    cfg.ping_interval_seconds = static_cast<uint32_t>((*sec)["ping_interval_seconds"].value_or(30));
    cfg.max_frame_size = static_cast<size_t>((*sec)["max_frame_size"].value_or(65536));
    return cfg;
}

ProxyConfig::TransactionConfig ConfigLoader::extract_transactions(const toml::table& root) {
    ProxyConfig::TransactionConfig cfg;
    const auto* sec = root["transactions"].as_table();
    if (!sec) return cfg;
    cfg.enabled = (*sec)["enabled"].value_or(false);
    cfg.timeout_ms = static_cast<uint32_t>((*sec)["timeout_ms"].value_or(30000));
    cfg.max_active_transactions = static_cast<uint32_t>((*sec)["max_active_transactions"].value_or(100));
    cfg.cleanup_interval_seconds = static_cast<uint32_t>((*sec)["cleanup_interval_seconds"].value_or(60));
    return cfg;
}

ProxyConfig::LlmConfig ConfigLoader::extract_llm(const toml::table& root) {
    ProxyConfig::LlmConfig cfg;
    const auto* sec = root["llm"].as_table();
    if (!sec) return cfg;
    cfg.enabled = (*sec)["enabled"].value_or(false);
    cfg.provider = (*sec)["provider"].value_or(std::string("openai"));
    cfg.endpoint = (*sec)["endpoint"].value_or(std::string("https://api.openai.com"));
    cfg.api_key = (*sec)["api_key"].value_or(std::string(""));
    cfg.default_model = (*sec)["default_model"].value_or(std::string("gpt-4"));
    cfg.timeout_ms = static_cast<uint32_t>((*sec)["timeout_ms"].value_or(30000));
    cfg.max_retries = static_cast<uint32_t>((*sec)["max_retries"].value_or(2));
    cfg.max_requests_per_minute = static_cast<uint32_t>((*sec)["max_requests_per_minute"].value_or(60));
    cfg.cache_enabled = (*sec)["cache_enabled"].value_or(true);
    cfg.cache_max_entries = static_cast<size_t>((*sec)["cache_max_entries"].value_or(1000));
    cfg.cache_ttl_seconds = static_cast<uint32_t>((*sec)["cache_ttl_seconds"].value_or(3600));
    return cfg;
}

ProxyConfig::CostTrackingConfig ConfigLoader::extract_cost_tracking(const toml::table& root) {
    ProxyConfig::CostTrackingConfig cfg;
    const auto* sec = root["cost_tracking"].as_table();
    if (!sec) return cfg;
    cfg.enabled = (*sec)["enabled"].value_or(false);
    cfg.max_top_queries = static_cast<size_t>((*sec)["max_top_queries"].value_or(50));

    const auto* budget = (*sec)["default_budget"].as_table();
    if (budget) {
        cfg.default_daily_limit = (*budget)["daily_limit"].value_or(0.0);
        cfg.default_hourly_limit = (*budget)["hourly_limit"].value_or(0.0);
    }

    if (const auto* budgets = (*sec)["user_budgets"].as_table()) {
        for (const auto& [user, val] : *budgets) {
            const auto* t = val.as_table();
            if (!t) continue;
            ProxyConfig::CostTrackingConfig::UserBudget ub;
            ub.user = std::string(user);
            ub.daily_limit = (*t)["daily_limit"].value_or(0.0);
            ub.hourly_limit = (*t)["hourly_limit"].value_or(0.0);
            cfg.user_budgets.push_back(std::move(ub));
        }
    }
    return cfg;
}

ProxyConfig::AccessRequestConfig ConfigLoader::extract_access_requests(const toml::table& root) {
    ProxyConfig::AccessRequestConfig cfg;
    const auto* sec = root["access_requests"].as_table();
    if (!sec) return cfg;
    cfg.enabled = (*sec)["enabled"].value_or(false);
    cfg.max_duration_hours = static_cast<uint32_t>((*sec)["max_duration_hours"].value_or(168));
    cfg.default_duration_hours = static_cast<uint32_t>((*sec)["default_duration_hours"].value_or(24));
    cfg.max_pending_requests = static_cast<size_t>((*sec)["max_pending_requests"].value_or(100));
    cfg.cleanup_interval_seconds = static_cast<uint32_t>((*sec)["cleanup_interval_seconds"].value_or(60));
    return cfg;
}

RouteConfig ConfigLoader::extract_routes(const toml::table& root) {
    RouteConfig cfg;
    const auto* routes = root["routes"].as_table();
    if (!routes) return cfg;
    const auto& r = *routes;

    cfg.query              = r["query"].value_or(cfg.query);
    cfg.dry_run            = r["dry_run"].value_or(cfg.dry_run);
    cfg.health             = r["health"].value_or(cfg.health);
    cfg.metrics            = r["metrics"].value_or(cfg.metrics);
    cfg.openapi_spec       = r["openapi_spec"].value_or(cfg.openapi_spec);
    cfg.swagger_ui         = r["swagger_ui"].value_or(cfg.swagger_ui);
    cfg.policies_reload    = r["policies_reload"].value_or(cfg.policies_reload);
    cfg.config_validate    = r["config_validate"].value_or(cfg.config_validate);
    cfg.slow_queries       = r["slow_queries"].value_or(cfg.slow_queries);
    cfg.circuit_breakers   = r["circuit_breakers"].value_or(cfg.circuit_breakers);
    cfg.plugin_reload      = r["plugin_reload"].value_or(cfg.plugin_reload);
    cfg.pii_report         = r["pii_report"].value_or(cfg.pii_report);
    cfg.security_summary   = r["security_summary"].value_or(cfg.security_summary);
    cfg.lineage            = r["lineage"].value_or(cfg.lineage);
    cfg.data_subject_access = r["data_subject_access"].value_or(cfg.data_subject_access);
    cfg.schema_history     = r["schema_history"].value_or(cfg.schema_history);
    cfg.schema_pending     = r["schema_pending"].value_or(cfg.schema_pending);
    cfg.schema_approve     = r["schema_approve"].value_or(cfg.schema_approve);
    cfg.schema_reject      = r["schema_reject"].value_or(cfg.schema_reject);
    cfg.schema_drift       = r["schema_drift"].value_or(cfg.schema_drift);
    cfg.graphql            = r["graphql"].value_or(cfg.graphql);
    cfg.firewall_mode      = r["firewall_mode"].value_or(cfg.firewall_mode);
    cfg.firewall_allowlist = r["firewall_allowlist"].value_or(cfg.firewall_allowlist);
    cfg.nl_query           = r["nl_query"].value_or(cfg.nl_query);
    cfg.catalog_tables     = r["catalog_tables"].value_or(cfg.catalog_tables);
    cfg.catalog_search     = r["catalog_search"].value_or(cfg.catalog_search);
    cfg.catalog_stats      = r["catalog_stats"].value_or(cfg.catalog_stats);
    cfg.policy_simulate    = r["policy_simulate"].value_or(cfg.policy_simulate);
    cfg.compliance_report  = r["compliance_report"].value_or(cfg.compliance_report);
    cfg.cost_summary       = r["cost_summary"].value_or(cfg.cost_summary);
    cfg.cost_top           = r["cost_top"].value_or(cfg.cost_top);
    cfg.cost_stats         = r["cost_stats"].value_or(cfg.cost_stats);
    cfg.access_requests    = r["access_requests"].value_or(cfg.access_requests);
    return cfg;
}

void ConfigLoader::extract_features(const toml::table& root, ProxyConfig& config) {
    const auto* feat = root["features"].as_table();
    if (!feat) return;

    config.classification_enabled = (*feat)["classification"].value_or(config.classification_enabled);
    config.masking_enabled        = (*feat)["masking"].value_or(config.masking_enabled);
    config.openapi_enabled        = (*feat)["openapi"].value_or(config.openapi_enabled);
    config.dry_run_enabled        = (*feat)["dry_run"].value_or(config.dry_run_enabled);

    config.data_catalog_enabled       = (*feat)["data_catalog"].value_or(config.data_catalog_enabled);
    config.policy_simulator_enabled   = (*feat)["policy_simulator"].value_or(config.policy_simulator_enabled);
    config.cost_tracking_enabled      = (*feat)["cost_tracking"].value_or(config.cost_tracking_enabled);
    config.access_requests_enabled    = (*feat)["access_requests"].value_or(config.access_requests_enabled);
}

// ---- Shared extraction + validation ----------------------------------------

ProxyConfig ConfigLoader::extract_all_sections(const toml::table& tbl) {
    ProxyConfig config;
    config.server = extract_server(tbl);
    config.logging = extract_logging(tbl);
    config.databases = extract_databases(tbl);
    config.users = extract_users(tbl);
    config.policies = extract_policies(tbl);
    config.rate_limiting = extract_rate_limiting(tbl);
    config.cache = extract_cache(tbl);
    config.audit = extract_audit(tbl);
    config.classifiers = extract_classifiers(tbl);
    config.circuit_breaker = extract_circuit_breaker(tbl);
    config.allocator = extract_allocator(tbl);
    config.metrics = extract_metrics(tbl);
    config.config_watcher = extract_config_watcher(tbl);
    config.rls_rules = extract_rls_rules(tbl);
    config.rewrite_rules = extract_rewrite_rules(tbl);
    config.security = extract_security(tbl);
    config.encryption = extract_encryption(tbl);
    config.tenants = extract_tenants(tbl);
    config.plugins = extract_plugins(tbl);
    config.schema_management = extract_schema_management(tbl);
    config.wire_protocol = extract_wire_protocol(tbl);
    config.graphql = extract_graphql(tbl);
    config.binary_rpc = extract_binary_rpc(tbl);
    config.alerting = extract_alerting(tbl);
    config.auth = extract_auth(tbl);
    config.audit_sampling = extract_audit_sampling(tbl);
    config.result_cache = extract_result_cache(tbl);
    config.slow_query = extract_slow_query(tbl);
    config.query_cost = extract_query_cost(tbl);
    config.schema_drift = extract_schema_drift(tbl);
    config.retry = extract_retry(tbl);
    config.request_timeout = extract_request_timeout(tbl);
    config.audit_encryption = extract_audit_encryption(tbl);
    config.tracing = extract_tracing(tbl);
    config.adaptive_rate_limiting = extract_adaptive_rate_limiting(tbl);
    config.priority = extract_priority(tbl);
    config.data_residency = extract_data_residency(tbl);
    config.column_versioning = extract_column_versioning(tbl);
    config.synthetic_data = extract_synthetic_data(tbl);
    config.cost_based_rewriting = extract_cost_based_rewriting(tbl);
    config.distributed_rate_limiting = extract_distributed_rate_limiting(tbl);
    config.websocket = extract_websocket(tbl);
    config.transactions = extract_transactions(tbl);
    config.llm = extract_llm(tbl);
    config.cost_tracking = extract_cost_tracking(tbl);
    config.access_requests = extract_access_requests(tbl);
    config.routes = extract_routes(tbl);
    extract_features(tbl, config);
    return config;
}

ConfigLoader::LoadResult ConfigLoader::validate_and_return(ProxyConfig config) {
    const auto errors = validate_config(config);
    if (!errors.empty()) {
        std::string combined = "Config validation failed:";
        for (const auto& err : errors) { combined += "\n  - "; combined += err; }
        return ConfigLoader::LoadResult::error(std::move(combined));
    }
    return ConfigLoader::LoadResult::ok(std::move(config));
}

// ---- Public API ------------------------------------------------------------

ConfigLoader::LoadResult ConfigLoader::load_from_file(const std::string& config_path) {
    try {
        const auto tbl = parse_toml_file(config_path);
        return validate_and_return(extract_all_sections(tbl));
    } catch (const std::exception& e) {
        return LoadResult::error(std::format("Failed to load config: {}", e.what()));
    }
}

ConfigLoader::LoadResult ConfigLoader::load_from_string(const std::string& toml_content) {
    try {
        const auto tbl = parse_toml_string(toml_content);
        return validate_and_return(extract_all_sections(tbl));
    } catch (const std::exception& e) {
        return LoadResult::error(std::format("Failed to parse config: {}", e.what()));
    }
}

// ============================================================================
// Config Validation
// ============================================================================

std::vector<std::string> ConfigLoader::validate_config(const ProxyConfig& config) {
    std::vector<std::string> errors;

    if (!utils::in_range<1, 65535>(config.server.port)) {
        errors.push_back(std::format("server.port must be 1-65535, got {}", config.server.port));
    }

    if (config.server.tls.enabled) {
        if (config.server.tls.cert_file.empty()) {
            errors.push_back("server.tls.cert_file required when TLS is enabled");
        }
        if (config.server.tls.key_file.empty()) {
            errors.push_back("server.tls.key_file required when TLS is enabled");
        }
        if (config.server.tls.require_client_cert && config.server.tls.ca_file.empty()) {
            errors.push_back("server.tls.ca_file required when require_client_cert is true");
        }
    }

    for (size_t i = 0; i < config.databases.size(); ++i) {
        const auto& db = config.databases[i];
        if (db.name.empty()) {
            errors.push_back(std::format("databases[{}].name must not be empty", i));
        }
        if (db.connection_string.empty()) {
            errors.push_back(std::format("databases[{}].connection_string must not be empty", i));
        }
        if (db.min_connections > db.max_connections) {
            errors.push_back(std::format(
                "databases[{}].min_connections ({}) > max_connections ({})",
                i, db.min_connections, db.max_connections));
        }
    }

    if (config.rate_limiting.enabled) {
        if (config.rate_limiting.global_tokens_per_second == 0) {
            errors.push_back("rate_limiting.global.tokens_per_second must be > 0 when enabled");
        }
    }

    if (config.circuit_breaker.enabled) {
        if (config.circuit_breaker.failure_threshold <= 0) {
            errors.push_back("circuit_breaker.failure_threshold must be > 0");
        }
        if (config.circuit_breaker.timeout_ms <= 0) {
            errors.push_back("circuit_breaker.timeout_ms must be > 0");
        }
    }

    if (config.audit.webhook_enabled && config.audit.webhook_url.empty()) {
        errors.push_back("audit.webhook.url required when webhook is enabled");
    }

    return errors;
}

} // namespace sqlproxy
