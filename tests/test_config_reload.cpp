#include <catch2/catch_test_macros.hpp>
#include "config/config_loader.hpp"
#include "config/config_watcher.hpp"
#include "policy/policy_engine.hpp"
#include "server/rate_limiter.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>

using namespace sqlproxy;

// ============================================================================
// Helper: Write a TOML string to a temp file
// ============================================================================

static std::string write_temp_toml(const std::string& content, const std::string& suffix = "") {
    auto path = std::filesystem::temp_directory_path() /
                ("test_config" + suffix + "_" +
                 std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
                 ".toml");
    std::ofstream f(path);
    f << content;
    f.close();
    return path.string();
}

// ============================================================================
// ConfigLoader: New field extraction
// ============================================================================

TEST_CASE("ConfigLoader extracts new server fields", "[config]") {
    SECTION("max_sql_length from TOML") {
        auto result = ConfigLoader::load_from_string(R"(
            [server]
            host = "127.0.0.1"
            port = 9090
            max_sql_length = 204800
        )");

        REQUIRE(result.success);
        REQUIRE(result.config.server.host == "127.0.0.1");
        REQUIRE(result.config.server.port == 9090);
        REQUIRE(result.config.server.max_sql_length == 204800);
    }

    SECTION("max_sql_length defaults to 102400") {
        auto result = ConfigLoader::load_from_string(R"(
            [server]
            host = "0.0.0.0"
        )");

        REQUIRE(result.success);
        REQUIRE(result.config.server.max_sql_length == 102400);
    }
}

TEST_CASE("ConfigLoader extracts new database fields", "[config]") {
    auto result = ConfigLoader::load_from_string(R"(
        [[databases]]
        name = "mydb"
        type = "postgresql"
        connection_string = "postgresql://user:pass@localhost/mydb"
        min_connections = 4
        max_connections = 20
        connection_timeout_ms = 3000
        query_timeout_ms = 15000
        health_check_query = "SELECT 1 AS alive"
        health_check_interval_seconds = 30
        idle_timeout_seconds = 600
        pool_acquire_timeout_ms = 10000
        max_result_rows = 50000
    )");

    REQUIRE(result.success);
    REQUIRE(result.config.databases.size() == 1);

    const auto& db = result.config.databases[0];
    REQUIRE(db.name == "mydb");
    REQUIRE(db.health_check_query == "SELECT 1 AS alive");
    REQUIRE(db.health_check_interval_seconds == 30);
    REQUIRE(db.idle_timeout_seconds == 600);
    REQUIRE(db.pool_acquire_timeout_ms == 10000);
    REQUIRE(db.max_result_rows == 50000);
}

TEST_CASE("ConfigLoader extracts new audit fields", "[config]") {
    SECTION("Custom batch size and fsync interval") {
        auto result = ConfigLoader::load_from_string(R"(
            [audit]
            async_mode = true
            ring_buffer_size = 32768
            flush_interval_ms = 500
            max_batch_size = 2000
            fsync_interval_batches = 5

            [audit.file]
            output_file = "/tmp/test_audit.jsonl"
        )");

        REQUIRE(result.success);
        REQUIRE(result.config.audit.max_batch_size == 2000);
        REQUIRE(result.config.audit.fsync_interval_batches == 5);
        REQUIRE(result.config.audit.ring_buffer_size == 32768);
    }

    SECTION("Defaults when not specified") {
        auto result = ConfigLoader::load_from_string(R"(
            [audit]
            async_mode = true
        )");

        REQUIRE(result.success);
        REQUIRE(result.config.audit.max_batch_size == 1000);
        REQUIRE(result.config.audit.fsync_interval_batches == 10);
    }
}

TEST_CASE("ConfigLoader extracts config_watcher settings", "[config]") {
    SECTION("Custom values") {
        auto result = ConfigLoader::load_from_string(R"(
            [config_watcher]
            enabled = false
            poll_interval_seconds = 15
        )");

        REQUIRE(result.success);
        REQUIRE_FALSE(result.config.config_watcher.enabled);
        REQUIRE(result.config.config_watcher.poll_interval_seconds == 15);
    }

    SECTION("Defaults when section missing") {
        auto result = ConfigLoader::load_from_string(R"(
            [server]
            host = "0.0.0.0"
        )");

        REQUIRE(result.success);
        REQUIRE(result.config.config_watcher.enabled == true);
        REQUIRE(result.config.config_watcher.poll_interval_seconds == 5);
    }
}

// ============================================================================
// ConfigLoader: Full round-trip (write file, load, check)
// ============================================================================

TEST_CASE("ConfigLoader round-trip from file", "[config]") {
    std::string toml = R"(
        [server]
        host = "0.0.0.0"
        port = 8080
        admin_token = "secret123"
        max_sql_length = 51200

        [[databases]]
        name = "testdb"
        type = "postgresql"
        connection_string = "postgresql://user:pass@localhost/testdb"
        health_check_query = "SELECT 42"
        max_result_rows = 5000

        [[users]]
        name = "alice"
        roles = ["admin"]

        [[users]]
        name = "bob"
        roles = ["readonly"]

        [[policies]]
        name = "allow_select"
        priority = 50
        action = "ALLOW"
        users = ["*"]
        statement_types = ["SELECT"]

        [[policies]]
        name = "block_ddl"
        priority = 100
        action = "BLOCK"
        users = ["*"]
        statement_types = ["CREATE_TABLE", "DROP_TABLE"]

        [config_watcher]
        enabled = true
        poll_interval_seconds = 10
    )";

    auto path = write_temp_toml(toml);
    auto result = ConfigLoader::load_from_file(path);
    std::filesystem::remove(path);

    REQUIRE(result.success);
    REQUIRE(result.config.server.admin_token == "secret123");
    REQUIRE(result.config.server.max_sql_length == 51200);
    REQUIRE(result.config.databases[0].health_check_query == "SELECT 42");
    REQUIRE(result.config.databases[0].max_result_rows == 5000);
    REQUIRE(result.config.users.size() == 2);
    REQUIRE(result.config.users.count("alice") == 1);
    REQUIRE(result.config.users.count("bob") == 1);
    REQUIRE(result.config.policies.size() == 2);
    REQUIRE(result.config.config_watcher.poll_interval_seconds == 10);
}

// ============================================================================
// ConfigWatcher: Detects file changes and fires callback
// ============================================================================

TEST_CASE("ConfigWatcher detects file change and invokes callback", "[config_watcher]") {
    // Write initial config
    std::string initial = R"(
        [[policies]]
        name = "initial_policy"
        priority = 50
        action = "ALLOW"
        users = ["*"]
        statement_types = ["SELECT"]
    )";

    auto path = write_temp_toml(initial, "_watcher");

    std::atomic<int> callback_count{0};
    std::string last_policy_name;

    ConfigWatcher watcher(path, std::chrono::seconds{1});
    watcher.set_callback([&](const ProxyConfig& cfg) {
        callback_count.fetch_add(1);
        if (!cfg.policies.empty()) {
            last_policy_name = cfg.policies[0].name;
        }
    });
    watcher.start();
    REQUIRE(watcher.is_running());

    // Wait for watcher to settle
    std::this_thread::sleep_for(std::chrono::milliseconds{200});

    // Modify config file
    std::string updated = R"(
        [[policies]]
        name = "updated_policy"
        priority = 100
        action = "BLOCK"
        users = ["*"]
        statement_types = ["DROP_TABLE"]
    )";

    {
        std::ofstream f(path);
        f << updated;
    }

    // Wait for watcher to detect (poll interval = 1s, plus some margin)
    std::this_thread::sleep_for(std::chrono::milliseconds{2500});

    watcher.stop();
    REQUIRE_FALSE(watcher.is_running());

    // Verify callback was invoked with new config
    REQUIRE(callback_count.load() >= 1);
    REQUIRE(last_policy_name == "updated_policy");

    std::filesystem::remove(path);
}

TEST_CASE("ConfigWatcher handles invalid config gracefully", "[config_watcher]") {
    std::string valid = R"(
        [[policies]]
        name = "valid_policy"
        priority = 50
        action = "ALLOW"
        users = ["*"]
    )";

    auto path = write_temp_toml(valid, "_invalid");

    std::atomic<int> callback_count{0};

    ConfigWatcher watcher(path, std::chrono::seconds{1});
    watcher.set_callback([&](const ProxyConfig&) {
        callback_count.fetch_add(1);
    });
    watcher.start();

    std::this_thread::sleep_for(std::chrono::milliseconds{200});

    // Write invalid TOML (unclosed bracket)
    {
        std::ofstream f(path);
        f << "[[broken\nthis is not valid toml";
    }

    // Wait for watcher to detect
    std::this_thread::sleep_for(std::chrono::milliseconds{2500});

    watcher.stop();

    // Callback should NOT have been called (invalid config is rejected)
    REQUIRE(callback_count.load() == 0);

    std::filesystem::remove(path);
}

// ============================================================================
// PolicyEngine: Hot-reload via RCU
// ============================================================================

TEST_CASE("PolicyEngine hot-reload replaces policies atomically", "[policy_reload]") {
    PolicyEngine engine;

    // Load initial policies
    std::vector<Policy> initial;
    {
        Policy p;
        p.name = "allow_select";
        p.priority = 50;
        p.action = Decision::ALLOW;
        p.users = {"*"};
        p.scope.operations = {StatementType::SELECT};
        initial.push_back(p);
    }
    engine.load_policies(initial);
    REQUIRE(engine.policy_count() == 1);

    // Hot-reload with different policies
    std::vector<Policy> updated;
    {
        Policy p1;
        p1.name = "allow_select";
        p1.priority = 50;
        p1.action = Decision::ALLOW;
        p1.users = {"*"};
        p1.scope.operations = {StatementType::SELECT};
        updated.push_back(p1);

        Policy p2;
        p2.name = "block_ddl";
        p2.priority = 100;
        p2.action = Decision::BLOCK;
        p2.users = {"*"};
        p2.scope.operations = {StatementType::CREATE_TABLE, StatementType::DROP_TABLE};
        updated.push_back(p2);

        Policy p3;
        p3.name = "allow_insert";
        p3.priority = 50;
        p3.action = Decision::ALLOW;
        p3.users = {"*"};
        p3.scope.operations = {StatementType::INSERT};
        updated.push_back(p3);
    }
    engine.reload_policies(updated);
    REQUIRE(engine.policy_count() == 3);
}

TEST_CASE("PolicyEngine reload is safe under concurrent reads", "[policy_reload]") {
    PolicyEngine engine;

    // Load initial policy
    std::vector<Policy> initial;
    {
        Policy p;
        p.name = "allow_all";
        p.priority = 50;
        p.action = Decision::ALLOW;
        p.users = {"*"};
        p.scope.operations = {StatementType::SELECT};
        initial.push_back(p);
    }
    engine.load_policies(initial);

    // Prepare analysis for evaluation
    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    analysis.sub_type = "SELECT";
    TableRef ref;
    ref.table = "test_table";
    analysis.source_tables.push_back(ref);
    analysis.table_usage["test_table"] = TableUsage::READ;

    std::atomic<bool> stop{false};
    std::atomic<int> eval_count{0};
    std::atomic<int> errors{0};

    // Reader thread: continuously evaluate policies
    std::thread reader([&] {
        while (!stop.load()) {
            try {
                auto result = engine.evaluate("user1", {"user"}, "testdb", analysis);
                eval_count.fetch_add(1);
                // Should never crash — may get ALLOW or BLOCK depending on timing
                (void)result;
            } catch (...) {
                errors.fetch_add(1);
            }
        }
    });

    // Writer: reload policies multiple times
    for (int i = 0; i < 20; ++i) {
        std::vector<Policy> new_policies;
        Policy p;
        p.name = "policy_v" + std::to_string(i);
        p.priority = 50;
        p.action = (i % 2 == 0) ? Decision::ALLOW : Decision::BLOCK;
        p.users = {"*"};
        p.scope.operations = {StatementType::SELECT};
        new_policies.push_back(p);
        engine.reload_policies(new_policies);
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }

    stop.store(true);
    reader.join();

    // Should have executed many evaluations without crashes
    REQUIRE(eval_count.load() > 0);
    REQUIRE(errors.load() == 0);
}

// ============================================================================
// RateLimiter: Hot-reload per-user/per-db limits
// ============================================================================

TEST_CASE("RateLimiter accepts new per-user limits at runtime", "[rate_limit_reload]") {
    HierarchicalRateLimiter::Config config;
    config.global_tokens_per_second = 100000;
    config.global_burst_capacity = 100000;
    config.default_user_tokens_per_second = 5;
    config.default_user_burst_capacity = 5;
    config.default_db_tokens_per_second = 100000;
    config.default_db_burst_capacity = 100000;
    config.default_user_db_tokens_per_second = 100000;
    config.default_user_db_burst_capacity = 100000;

    HierarchicalRateLimiter limiter(config);

    // Default: user gets 5 tokens burst
    for (int i = 0; i < 5; ++i) {
        auto result = limiter.check("alice", "testdb");
        REQUIRE(result.allowed);
    }
    // 6th should be rejected
    auto denied = limiter.check("alice", "testdb");
    REQUIRE_FALSE(denied.allowed);

    // Hot-reload: increase alice's limit
    limiter.set_user_limit("alice", 1000, 1000);

    // Now alice should be able to make many more requests
    int allowed_count = 0;
    for (int i = 0; i < 100; ++i) {
        auto result = limiter.check("alice", "testdb");
        if (result.allowed) ++allowed_count;
    }
    REQUIRE(allowed_count > 50);
}

TEST_CASE("RateLimiter accepts new per-database limits at runtime", "[rate_limit_reload]") {
    HierarchicalRateLimiter::Config config;
    config.global_tokens_per_second = 100000;
    config.global_burst_capacity = 100000;
    config.default_user_tokens_per_second = 100000;
    config.default_user_burst_capacity = 100000;
    config.default_db_tokens_per_second = 3;
    config.default_db_burst_capacity = 3;
    config.default_user_db_tokens_per_second = 100000;
    config.default_user_db_burst_capacity = 100000;

    HierarchicalRateLimiter limiter(config);

    // Default: db gets 3 tokens burst
    for (int i = 0; i < 3; ++i) {
        auto result = limiter.check("user1", "mydb");
        REQUIRE(result.allowed);
    }
    auto denied = limiter.check("user1", "mydb");
    REQUIRE_FALSE(denied.allowed);

    // Hot-reload: increase db limit
    limiter.set_database_limit("mydb", 10000, 10000);

    int allowed_count = 0;
    for (int i = 0; i < 50; ++i) {
        auto result = limiter.check("user1", "mydb");
        if (result.allowed) ++allowed_count;
    }
    REQUIRE(allowed_count > 20);
}

// ============================================================================
// End-to-end: ConfigWatcher triggers PolicyEngine reload
// ============================================================================

TEST_CASE("ConfigWatcher triggers PolicyEngine reload end-to-end", "[integration]") {
    auto engine = std::make_shared<PolicyEngine>();

    // Initial: 1 policy
    std::string initial = R"(
        [[policies]]
        name = "allow_select"
        priority = 50
        action = "ALLOW"
        users = ["*"]
        statement_types = ["SELECT"]
    )";

    auto path = write_temp_toml(initial, "_e2e");
    auto load_result = ConfigLoader::load_from_file(path);
    REQUIRE(load_result.success);
    engine->load_policies(load_result.config.policies);
    REQUIRE(engine->policy_count() == 1);

    // Start watcher with callback that reloads policies
    std::atomic<bool> reloaded{false};

    ConfigWatcher watcher(path, std::chrono::seconds{1});
    watcher.set_callback([&engine, &reloaded](const ProxyConfig& cfg) {
        engine->reload_policies(cfg.policies);
        reloaded.store(true);
    });
    watcher.start();

    std::this_thread::sleep_for(std::chrono::milliseconds{200});

    // Add a second policy to the file
    std::string updated = R"(
        [[policies]]
        name = "allow_select"
        priority = 50
        action = "ALLOW"
        users = ["*"]
        statement_types = ["SELECT"]

        [[policies]]
        name = "block_ddl"
        priority = 100
        action = "BLOCK"
        users = ["*"]
        statement_types = ["CREATE_TABLE", "DROP_TABLE"]
    )";

    {
        std::ofstream f(path);
        f << updated;
    }

    // Wait for reload
    std::this_thread::sleep_for(std::chrono::milliseconds{2500});
    watcher.stop();

    REQUIRE(reloaded.load());
    REQUIRE(engine->policy_count() == 2);

    std::filesystem::remove(path);
}
