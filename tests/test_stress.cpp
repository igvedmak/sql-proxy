#include <catch2/catch_test_macros.hpp>

#include "server/rate_limiter.hpp"
#include "parser/parse_cache.hpp"
#include "db/postgresql/pg_sql_parser.hpp"
#include "policy/policy_engine.hpp"
#include "classifier/classifier_registry.hpp"
#include "audit/audit_emitter.hpp"
#include "core/pipeline.hpp"
#include "db/iquery_executor.hpp"
#include "analyzer/sql_analyzer.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <numeric>
#include <random>
#include <string>
#include <thread>
#include <vector>

using namespace sqlproxy;

// ============================================================================
// Mock Executor — returns canned QueryResult (thread-safe, no shared state)
// ============================================================================

namespace {

class MockExecutor : public IQueryExecutor {
public:
    explicit MockExecutor(bool should_succeed = true)
        : should_succeed_(should_succeed) {}

    QueryResult execute(const std::string& /*sql*/, StatementType /*stmt_type*/) override {
        QueryResult result;
        result.success = should_succeed_;
        if (should_succeed_) {
            result.column_names = {"id", "name", "email"};
            result.column_type_oids = {23, 25, 25};
            result.rows = {
                {"1", "Alice", "alice@example.com"},
                {"2", "Bob", "bob@test.org"}
            };
            result.affected_rows = 0;
            result.execution_time = std::chrono::microseconds(100);
        } else {
            result.error_code = ErrorCode::DATABASE_ERROR;
            result.error_message = "Mock database error";
        }
        return result;
    }

private:
    bool should_succeed_;
};

// ============================================================================
// Helpers
// ============================================================================

ProxyRequest make_request(
    const std::string& user,
    const std::string& sql,
    const std::string& database = "testdb",
    const std::vector<std::string>& roles = {"user"})
{
    static std::atomic<uint64_t> counter{0};
    ProxyRequest req;
    req.request_id = "stress-" + std::to_string(counter.fetch_add(1));
    req.user = user;
    req.roles = roles;
    req.sql = sql;
    req.source_ip = "127.0.0.1";
    req.session_id = "sess-" + user;
    req.database = database;
    req.received_at = std::chrono::system_clock::now();
    return req;
}

Policy make_allow_policy(const std::string& name,
                         const std::string& table = "",
                         const std::string& schema = "") {
    Policy p;
    p.name = name;
    p.priority = 0;
    p.action = Decision::ALLOW;
    p.users.insert("*");
    if (!table.empty()) p.scope.table = table;
    if (!schema.empty()) p.scope.schema = schema;
    p.scope.operations = {
        StatementType::SELECT, StatementType::INSERT,
        StatementType::UPDATE, StatementType::DELETE
    };
    return p;
}

AnalysisResult make_select_analysis(const std::string& table,
                                     const std::string& schema = "") {
    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    analysis.sub_type = "SELECT";
    TableRef ref;
    ref.table = table;
    ref.schema = schema;
    analysis.source_tables.push_back(ref);
    analysis.table_usage[ref.full_name()] = TableUsage::READ;
    return analysis;
}

HierarchicalRateLimiter::Config make_stress_rl_config(
    uint32_t global_tps = 100000, uint32_t global_burst = 50000,
    uint32_t user_tps = 10000, uint32_t user_burst = 5000,
    uint32_t db_tps = 50000, uint32_t db_burst = 20000,
    uint32_t user_db_tps = 5000, uint32_t user_db_burst = 2000)
{
    HierarchicalRateLimiter::Config cfg;
    cfg.global_tokens_per_second = global_tps;
    cfg.global_burst_capacity = global_burst;
    cfg.default_user_tokens_per_second = user_tps;
    cfg.default_user_burst_capacity = user_burst;
    cfg.default_db_tokens_per_second = db_tps;
    cfg.default_db_burst_capacity = db_burst;
    cfg.default_user_db_tokens_per_second = user_db_tps;
    cfg.default_user_db_burst_capacity = user_db_burst;
    return cfg;
}

// Build a full pipeline with mock executor for stress testing
struct TestPipeline {
    std::shared_ptr<ParseCache> cache;
    std::shared_ptr<PgSqlParser> parser;
    std::shared_ptr<PolicyEngine> policy_engine;
    std::shared_ptr<HierarchicalRateLimiter> rate_limiter;
    std::shared_ptr<MockExecutor> executor;
    std::shared_ptr<ClassifierRegistry> classifier;
    std::shared_ptr<AuditEmitter> audit;
    std::shared_ptr<Pipeline> pipeline;

    TestPipeline(const std::vector<Policy>& policies,
                 const HierarchicalRateLimiter::Config& rl_config)
    {
        cache = std::make_shared<ParseCache>(10000, 16);
        parser = std::make_shared<PgSqlParser>(cache);
        policy_engine = std::make_shared<PolicyEngine>();
        policy_engine->load_policies(policies);
        rate_limiter = std::make_shared<HierarchicalRateLimiter>(rl_config);
        executor = std::make_shared<MockExecutor>(true);
        classifier = std::make_shared<ClassifierRegistry>();
        audit = std::make_shared<AuditEmitter>("/dev/null");
        pipeline = PipelineBuilder()
            .with_parser(parser)
            .with_policy_engine(policy_engine)
            .with_rate_limiter(rate_limiter)
            .with_executor(executor)
            .with_classifier(classifier)
            .with_audit_emitter(audit)
            .build();
    }
};

} // anonymous namespace

// ============================================================================
// Category 1: Rate Limiter Stress
// ============================================================================

TEST_CASE("Stress: Rate limiter 8-thread concurrent check correctness", "[stress][rate_limiter]") {
    // Tight global limit so we can verify allowed <= burst + tps*elapsed
    auto cfg = make_stress_rl_config(
        /*global_tps=*/1000, /*global_burst=*/500,
        /*user_tps=*/100000, /*user_burst=*/100000,
        /*db_tps=*/100000, /*db_burst=*/100000,
        /*user_db_tps=*/100000, /*user_db_burst=*/100000);
    HierarchicalRateLimiter limiter(cfg);

    constexpr int num_threads = 8;
    std::atomic<uint64_t> allowed_count{0};
    std::atomic<uint64_t> denied_count{0};
    std::atomic<bool> go{false};

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&] {
            while (!go.load(std::memory_order_acquire)) {}
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
            while (std::chrono::steady_clock::now() < deadline) {
                auto result = limiter.check("stress_user", "stress_db");
                if (result.allowed)
                    allowed_count.fetch_add(1, std::memory_order_relaxed);
                else
                    denied_count.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    auto start = std::chrono::steady_clock::now();
    go.store(true, std::memory_order_release);
    for (auto& t : threads) t.join();
    auto elapsed_s = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - start).count();

    auto stats = limiter.get_stats();
    // Generous tolerance: burst + tps*elapsed*3 (accounts for timing jitter, CAS races, thread overhead)
    uint64_t max_expected = static_cast<uint64_t>(500 + 1000 * elapsed_s * 3);

    REQUIRE(allowed_count.load() + denied_count.load() == stats.total_checks);
    REQUIRE(allowed_count.load() <= max_expected);
    REQUIRE(allowed_count.load() >= 400); // At least most of burst capacity
    REQUIRE(stats.total_checks > 1000);   // Enough iterations happened
}

TEST_CASE("Stress: Rate limiter 16-thread different users no interference", "[stress][rate_limiter]") {
    auto cfg = make_stress_rl_config(
        /*global_tps=*/1000000, /*global_burst=*/500000,
        /*user_tps=*/500, /*user_burst=*/200,
        /*db_tps=*/1000000, /*db_burst=*/500000,
        /*user_db_tps=*/1000000, /*user_db_burst=*/500000);
    HierarchicalRateLimiter limiter(cfg);

    constexpr int num_threads = 16;
    std::vector<uint64_t> per_thread_allowed(num_threads, 0);
    std::atomic<bool> go{false};

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&, i] {
            while (!go.load(std::memory_order_acquire)) {}
            std::string user = "user_" + std::to_string(i);
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
            while (std::chrono::steady_clock::now() < deadline) {
                auto result = limiter.check(user, "testdb");
                if (result.allowed) ++per_thread_allowed[i];
            }
        });
    }

    go.store(true, std::memory_order_release);
    for (auto& t : threads) t.join();

    // Each user should have gotten at least their burst capacity
    for (int i = 0; i < num_threads; ++i) {
        REQUIRE(per_thread_allowed[i] >= 200); // burst_capacity
    }

    // No user should have gotten wildly more than burst + tps*0.5s + tolerance
    for (int i = 0; i < num_threads; ++i) {
        REQUIRE(per_thread_allowed[i] <= 200 + 500 * 1 + 100); // burst + tps*0.5 + tolerance
    }
}

TEST_CASE("Stress: Rate limiter bucket creation under contention", "[stress][rate_limiter]") {
    auto cfg = make_stress_rl_config();
    cfg.default_user_burst_capacity = 100;
    HierarchicalRateLimiter limiter(cfg);

    constexpr int num_threads = 8;
    std::atomic<bool> go{false};
    std::atomic<uint64_t> allowed{0};
    std::atomic<uint64_t> total{0};

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&] {
            while (!go.load(std::memory_order_acquire)) {}
            // All threads create the same bucket simultaneously
            auto result = limiter.check("brand_new_user", "brand_new_db");
            total.fetch_add(1);
            if (result.allowed) allowed.fetch_add(1);
        });
    }

    go.store(true, std::memory_order_release);
    for (auto& t : threads) t.join();

    REQUIRE(total.load() == num_threads);
    // All 8 should be allowed (burst=100, only 8 requests)
    REQUIRE(allowed.load() == num_threads);
    REQUIRE(limiter.get_stats().total_checks == static_cast<uint64_t>(num_threads));
}

TEST_CASE("Stress: Rate limiter 8 threads random users no data races", "[stress][rate_limiter]") {
    auto cfg = make_stress_rl_config();
    HierarchicalRateLimiter limiter(cfg);

    constexpr int num_threads = 8;
    std::atomic<bool> go{false};
    std::atomic<uint64_t> total_allowed{0};
    std::atomic<uint64_t> total_denied{0};

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&, i] {
            while (!go.load(std::memory_order_acquire)) {}
            std::mt19937 rng(42 + i);
            std::uniform_int_distribution<int> user_dist(0, 4);
            std::uniform_int_distribution<int> db_dist(0, 2);
            std::string users[] = {"alice", "bob", "carol", "dave", "eve"};
            std::string dbs[] = {"prod", "staging", "analytics"};

            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
            while (std::chrono::steady_clock::now() < deadline) {
                auto result = limiter.check(users[user_dist(rng)], dbs[db_dist(rng)]);
                if (result.allowed)
                    total_allowed.fetch_add(1, std::memory_order_relaxed);
                else
                    total_denied.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    go.store(true, std::memory_order_release);
    for (auto& t : threads) t.join();

    auto stats = limiter.get_stats();
    REQUIRE(stats.total_checks > 0);
    REQUIRE(stats.total_checks == total_allowed.load() + total_denied.load());
}

// ============================================================================
// Category 2: Parse Cache Contention
// ============================================================================

TEST_CASE("Stress: Parse cache 8 threads same query contention", "[stress][parse_cache]") {
    auto cache = std::make_shared<ParseCache>(1000, 4);
    auto parser = std::make_shared<PgSqlParser>(cache);

    constexpr int num_threads = 8;
    constexpr int iterations = 1000;
    std::atomic<int> successes{0};
    std::atomic<int> failures{0};

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&] {
            for (int j = 0; j < iterations; ++j) {
                auto result = parser->parse("SELECT * FROM users WHERE id = 1");
                if (result.success)
                    successes.fetch_add(1, std::memory_order_relaxed);
                else
                    failures.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    for (auto& t : threads) t.join();

    auto stats = cache->get_stats();
    REQUIRE(successes.load() == num_threads * iterations);
    REQUIRE(failures.load() == 0);
    // Most should be cache hits (only the first parse per thread is a potential miss)
    REQUIRE(stats.hits >= static_cast<size_t>(num_threads * iterations - num_threads));
}

TEST_CASE("Stress: Parse cache 8 threads different queries no contention", "[stress][parse_cache]") {
    auto cache = std::make_shared<ParseCache>(10000, 16);
    auto parser = std::make_shared<PgSqlParser>(cache);

    constexpr int num_threads = 8;
    constexpr int iterations = 500;
    std::atomic<int> successes{0};

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&, i] {
            // Each thread has a unique query
            std::string sql = "SELECT * FROM table_" + std::to_string(i) + " WHERE id = 1";
            for (int j = 0; j < iterations; ++j) {
                auto result = parser->parse(sql);
                if (result.success) successes.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    for (auto& t : threads) t.join();

    auto stats = cache->get_stats();
    REQUIRE(successes.load() == num_threads * iterations);
    REQUIRE(stats.total_entries == static_cast<size_t>(num_threads)); // 8 unique queries
    REQUIRE(stats.hits >= static_cast<size_t>(num_threads * iterations - num_threads));
}

TEST_CASE("Stress: Parse cache eviction under pressure", "[stress][parse_cache]") {
    // Tiny cache: 10 entries, 2 shards = 5 per shard
    auto cache = std::make_shared<ParseCache>(10, 2);
    auto parser = std::make_shared<PgSqlParser>(cache);

    constexpr int num_threads = 4;
    constexpr int iterations = 100;
    std::atomic<int> successes{0};

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&, i] {
            for (int j = 0; j < iterations; ++j) {
                // Different table names produce different fingerprints
                // (literal values are normalized, but table names are not)
                std::string sql = "SELECT * FROM t_" +
                                  std::to_string(i * iterations + j) + " WHERE x = 1";
                auto result = parser->parse(sql);
                if (result.success) successes.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    for (auto& t : threads) t.join();

    auto stats = cache->get_stats();
    REQUIRE(successes.load() == num_threads * iterations);
    REQUIRE(stats.evictions > 0);         // Evictions happened (400 unique queries into 10-entry cache)
    REQUIRE(stats.total_entries <= 10);    // Cache respects max_entries
}

TEST_CASE("Stress: Parse cache stats consistency", "[stress][parse_cache]") {
    auto cache = std::make_shared<ParseCache>(1000, 8);
    auto parser = std::make_shared<PgSqlParser>(cache);

    constexpr int num_threads = 4;
    constexpr int iterations = 200;

    // 5 distinct queries per thread
    std::vector<std::string> queries = {
        "SELECT * FROM users",
        "SELECT * FROM orders WHERE id = 1",
        "SELECT name FROM customers",
        "SELECT COUNT(*) FROM orders",
        "SELECT * FROM users WHERE name = 'test'"
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&, i] {
            for (int j = 0; j < iterations; ++j) {
                parser->parse(queries[j % queries.size()]);
            }
        });
    }

    for (auto& t : threads) t.join();

    auto stats = cache->get_stats();
    size_t total_lookups = num_threads * iterations;
    REQUIRE(stats.hits + stats.misses == total_lookups);
    REQUIRE(stats.total_entries <= queries.size());
    REQUIRE(stats.hit_rate() > 0.5);
}

// ============================================================================
// Category 3: Policy Engine Concurrent Reload
// ============================================================================

TEST_CASE("Stress: Policy engine 8 readers + 1 writer for 2 seconds", "[stress][policy_engine]") {
    PolicyEngine engine;

    // Initial policy
    std::vector<Policy> initial;
    initial.push_back(make_allow_policy("allow_customers", "customers"));
    engine.load_policies(initial);

    constexpr int num_readers = 8;
    std::atomic<bool> stop{false};
    std::atomic<uint64_t> eval_count{0};
    std::atomic<uint64_t> errors{0};
    std::atomic<uint64_t> allows{0};
    std::atomic<uint64_t> blocks{0};

    auto analysis = make_select_analysis("customers");

    // Reader threads
    std::vector<std::thread> readers;
    for (int i = 0; i < num_readers; ++i) {
        readers.emplace_back([&] {
            while (!stop.load(std::memory_order_acquire)) {
                try {
                    auto result = engine.evaluate("user1", {"user"}, "testdb", analysis);
                    eval_count.fetch_add(1, std::memory_order_relaxed);
                    if (result.decision == Decision::ALLOW)
                        allows.fetch_add(1, std::memory_order_relaxed);
                    else
                        blocks.fetch_add(1, std::memory_order_relaxed);
                } catch (...) {
                    errors.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    // Writer thread: alternates between ALLOW and BLOCK
    std::thread writer([&] {
        for (int i = 0; !stop.load(std::memory_order_acquire); ++i) {
            std::vector<Policy> policies;
            Policy p;
            p.name = "policy_v" + std::to_string(i);
            p.priority = 50;
            p.action = (i % 2 == 0) ? Decision::ALLOW : Decision::BLOCK;
            p.users.insert("*");
            p.scope.table = "customers";
            p.scope.operations = {StatementType::SELECT};
            policies.push_back(p);
            engine.reload_policies(policies);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    });

    std::this_thread::sleep_for(std::chrono::seconds(2));
    stop.store(true, std::memory_order_release);
    writer.join();
    for (auto& r : readers) r.join();

    REQUIRE(errors.load() == 0);
    REQUIRE(eval_count.load() > 1000);
    REQUIRE(allows.load() + blocks.load() == eval_count.load());
}

TEST_CASE("Stress: Policy engine evaluation results always valid", "[stress][policy_engine]") {
    PolicyEngine engine;

    std::vector<Policy> initial;
    initial.push_back(make_allow_policy("allow_orders", "orders"));
    engine.load_policies(initial);

    constexpr int num_readers = 4;
    std::atomic<bool> stop{false};
    std::atomic<uint64_t> valid_results{0};
    std::atomic<uint64_t> invalid_results{0};

    auto analysis = make_select_analysis("orders");

    std::vector<std::thread> readers;
    for (int i = 0; i < num_readers; ++i) {
        readers.emplace_back([&] {
            while (!stop.load(std::memory_order_acquire)) {
                auto result = engine.evaluate("user1", {"user"}, "testdb", analysis);
                // Verify result is valid — decision must be ALLOW or BLOCK
                bool valid = (result.decision == Decision::ALLOW ||
                              result.decision == Decision::BLOCK);
                // When ALLOW, matched_policy must not be empty
                if (result.decision == Decision::ALLOW) {
                    valid = valid && !result.matched_policy.empty();
                }
                if (valid)
                    valid_results.fetch_add(1, std::memory_order_relaxed);
                else
                    invalid_results.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    // Writer reloads with named policies
    std::thread writer([&] {
        for (int i = 0; !stop.load(std::memory_order_acquire); ++i) {
            std::vector<Policy> policies;
            Policy p;
            p.name = "policy_v" + std::to_string(i);
            p.priority = 50;
            p.action = (i % 2 == 0) ? Decision::ALLOW : Decision::BLOCK;
            p.users.insert("*");
            p.scope.table = "orders";
            p.scope.operations = {StatementType::SELECT};
            policies.push_back(p);
            engine.reload_policies(policies);
            std::this_thread::sleep_for(std::chrono::milliseconds(3));
        }
    });

    std::this_thread::sleep_for(std::chrono::seconds(1));
    stop.store(true, std::memory_order_release);
    writer.join();
    for (auto& r : readers) r.join();

    REQUIRE(invalid_results.load() == 0);
    REQUIRE(valid_results.load() > 100);
}

// ============================================================================
// Category 4: Full Pipeline Stress
// ============================================================================

TEST_CASE("Stress: Pipeline 8 threads SELECT through full stack", "[stress][pipeline]") {
    std::vector<Policy> policies = {
        make_allow_policy("allow_users", "users"),
        make_allow_policy("allow_customers", "customers"),
        make_allow_policy("allow_orders", "orders")
    };
    auto rl_config = make_stress_rl_config();
    TestPipeline tp(policies, rl_config);

    constexpr int num_threads = 8;
    constexpr int iterations = 500;
    std::atomic<int> successes{0};
    std::atomic<int> failures{0};
    std::atomic<int> exceptions{0};

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&, i] {
            for (int j = 0; j < iterations; ++j) {
                try {
                    auto req = make_request("user_" + std::to_string(i),
                                            "SELECT * FROM users WHERE id = 1");
                    auto resp = tp.pipeline->execute(req);
                    if (resp.success)
                        successes.fetch_add(1, std::memory_order_relaxed);
                    else
                        failures.fetch_add(1, std::memory_order_relaxed);
                } catch (...) {
                    exceptions.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    for (auto& t : threads) t.join();
    tp.audit->shutdown();

    REQUIRE(exceptions.load() == 0);
    REQUIRE(successes.load() == num_threads * iterations);
    REQUIRE(tp.audit->get_stats().total_emitted >= static_cast<uint64_t>(num_threads * iterations));
}

TEST_CASE("Stress: Pipeline mixed query types", "[stress][pipeline]") {
    // ALLOW SELECT on users, BLOCK everything else
    std::vector<Policy> policies;
    Policy allow_select;
    allow_select.name = "allow_select_users";
    allow_select.priority = 50;
    allow_select.action = Decision::ALLOW;
    allow_select.users.insert("*");
    allow_select.scope.table = "users";
    allow_select.scope.operations = {StatementType::SELECT};
    policies.push_back(allow_select);

    Policy block_ddl;
    block_ddl.name = "block_all_ddl";
    block_ddl.priority = 100;
    block_ddl.action = Decision::BLOCK;
    block_ddl.users.insert("*");
    block_ddl.scope.operations = {
        StatementType::CREATE_TABLE, StatementType::DROP_TABLE, StatementType::ALTER_TABLE};
    policies.push_back(block_ddl);

    auto rl_config = make_stress_rl_config();
    TestPipeline tp(policies, rl_config);

    constexpr int num_threads = 8;
    constexpr int iterations = 200;
    std::atomic<int> select_ok{0};
    std::atomic<int> insert_blocked{0};
    std::atomic<int> ddl_blocked{0};
    std::atomic<int> exceptions{0};

    std::vector<std::string> selects = {
        "SELECT * FROM users WHERE id = 1",
        "SELECT name FROM users"
    };
    std::vector<std::string> inserts = {
        "INSERT INTO users (name) VALUES ('test')"
    };
    std::vector<std::string> ddls = {
        "CREATE TABLE temp_test (id INT)"
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&, i] {
            std::mt19937 rng(42 + i);
            std::uniform_int_distribution<int> dist(0, 99);

            for (int j = 0; j < iterations; ++j) {
                try {
                    int roll = dist(rng);
                    ProxyRequest req;
                    if (roll < 70) {
                        req = make_request("user1", selects[roll % selects.size()]);
                    } else if (roll < 90) {
                        req = make_request("user1", inserts[0]);
                    } else {
                        req = make_request("user1", ddls[0]);
                    }

                    auto resp = tp.pipeline->execute(req);

                    if (roll < 70 && resp.success)
                        select_ok.fetch_add(1, std::memory_order_relaxed);
                    else if (roll >= 70 && roll < 90 && !resp.success)
                        insert_blocked.fetch_add(1, std::memory_order_relaxed);
                    else if (roll >= 90 && !resp.success)
                        ddl_blocked.fetch_add(1, std::memory_order_relaxed);
                } catch (...) {
                    exceptions.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    for (auto& t : threads) t.join();
    tp.audit->shutdown();

    REQUIRE(exceptions.load() == 0);
    REQUIRE(select_ok.load() > 0);
    REQUIRE(insert_blocked.load() > 0);
    REQUIRE(ddl_blocked.load() > 0);
}

TEST_CASE("Stress: Pipeline with tight rate limiting", "[stress][pipeline]") {
    std::vector<Policy> policies = {
        make_allow_policy("allow_users", "users")
    };
    // Tight global limit: burst=50, tps=100
    auto rl_config = make_stress_rl_config(
        /*global_tps=*/100, /*global_burst=*/50,
        /*user_tps=*/100000, /*user_burst=*/100000,
        /*db_tps=*/100000, /*db_burst=*/100000,
        /*user_db_tps=*/100000, /*user_db_burst=*/100000);
    TestPipeline tp(policies, rl_config);

    constexpr int num_threads = 8;
    std::atomic<int> allowed{0};
    std::atomic<int> rate_limited{0};
    std::atomic<int> total{0};
    std::atomic<int> exceptions{0};

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&, i] {
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
            while (std::chrono::steady_clock::now() < deadline) {
                try {
                    auto req = make_request("user_" + std::to_string(i),
                                            "SELECT * FROM users WHERE id = 1");
                    auto resp = tp.pipeline->execute(req);
                    total.fetch_add(1, std::memory_order_relaxed);
                    if (resp.success)
                        allowed.fetch_add(1, std::memory_order_relaxed);
                    else if (resp.error_code == ErrorCode::RATE_LIMITED)
                        rate_limited.fetch_add(1, std::memory_order_relaxed);
                } catch (...) {
                    exceptions.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    for (auto& t : threads) t.join();
    tp.audit->shutdown();

    REQUIRE(exceptions.load() == 0);
    REQUIRE(allowed.load() > 0);          // Some requests succeeded
    REQUIRE(rate_limited.load() > 0);     // Some were rate-limited
    REQUIRE(total.load() == allowed.load() + rate_limited.load());
}

// ============================================================================
// Category 5: Audit Emitter Ring Buffer Stress
// ============================================================================

TEST_CASE("Stress: Audit emitter 8 threads emit max speed", "[stress][audit]") {
    // Heap-allocate: ring buffer is ~30MB (65536 × alignas(64) slots), too large for stack
    auto audit = std::make_unique<AuditEmitter>("/dev/null");

    constexpr int num_threads = 8;
    std::vector<uint64_t> per_thread_count(num_threads, 0);

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&, i] {
            AuditRecord record;
            record.user = "stress_user_" + std::to_string(i);
            record.sql = "SELECT 1";
            record.statement_type = StatementType::SELECT;

            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
            while (std::chrono::steady_clock::now() < deadline) {
                audit->emit(record);
                ++per_thread_count[i];
            }
        });
    }

    for (auto& t : threads) t.join();
    audit->flush();

    auto stats = audit->get_stats();
    uint64_t total_emitted_by_threads = 0;
    for (int i = 0; i < num_threads; ++i) {
        total_emitted_by_threads += per_thread_count[i];
    }

    REQUIRE(stats.total_emitted == total_emitted_by_threads);
    REQUIRE(stats.total_written <= stats.total_emitted);
    REQUIRE(stats.total_emitted > 1000);
}

TEST_CASE("Stress: Audit emitter overflow detection", "[stress][audit]") {
    AuditConfig config;
    config.output_file = "/dev/null";
    config.batch_flush_interval = std::chrono::milliseconds(5000); // 5s — very slow flush
    auto audit = std::make_unique<AuditEmitter>(config);

    constexpr int num_threads = 4;
    constexpr int emits_per_thread = 100000;
    std::vector<std::thread> threads;

    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&] {
            AuditRecord record;
            record.user = "overflow_user";
            record.sql = "SELECT 1";
            for (int j = 0; j < emits_per_thread; ++j) {
                audit->emit(record);
            }
        });
    }

    for (auto& t : threads) t.join();

    auto stats = audit->get_stats();
    // Ring buffer is 65536 — with 400K emits and slow flush, overflow is expected
    REQUIRE(stats.total_emitted > 0);
    REQUIRE(stats.total_written <= stats.total_emitted);

    audit->shutdown();
}

TEST_CASE("Stress: Audit emitter shutdown + late emit safety", "[stress][audit]") {
    auto audit = std::make_unique<AuditEmitter>("/dev/null");

    // Emit some records
    AuditRecord record;
    record.user = "test_user";
    record.sql = "SELECT 1";
    for (int i = 0; i < 100; ++i) {
        audit->emit(record);
    }
    audit->flush();

    auto stats_before = audit->get_stats();
    REQUIRE(stats_before.total_emitted == 100);

    audit->shutdown();

    // Post-shutdown emit should not crash
    for (int i = 0; i < 100; ++i) {
        audit->emit(record);
    }

    // Should not crash — that's the main assertion
    REQUIRE(true);
}

TEST_CASE("Stress: Audit emitter flush correctness", "[stress][audit]") {
    auto audit = std::make_unique<AuditEmitter>("/dev/null");

    AuditRecord record;
    record.user = "flush_user";
    record.sql = "SELECT 1";
    record.statement_type = StatementType::SELECT;

    for (int i = 0; i < 1000; ++i) {
        audit->emit(record);
    }

    audit->flush();
    auto stats = audit->get_stats();

    REQUIRE(stats.total_emitted == 1000);
    REQUIRE(stats.total_written == stats.total_emitted);
    REQUIRE(stats.flush_count >= 1);
}

// ============================================================================
// Category 6: Edge Cases
// ============================================================================

TEST_CASE("Edge: Empty SQL string through pipeline", "[edge][pipeline]") {
    std::vector<Policy> policies = {make_allow_policy("allow_all", "users")};
    auto rl_config = make_stress_rl_config();
    TestPipeline tp(policies, rl_config);

    auto req = make_request("user1", "");
    auto resp = tp.pipeline->execute(req);

    REQUIRE_FALSE(resp.success);
    REQUIRE(resp.error_code == ErrorCode::PARSE_ERROR);
    tp.audit->shutdown();
}

TEST_CASE("Edge: SQL with only whitespace", "[edge][parser]") {
    PgSqlParser parser;
    auto result = parser.parse("   \t\n  ");

    REQUIRE_FALSE(result.success);
    REQUIRE(result.error_code == ISqlParser::ErrorCode::EMPTY_QUERY);
}

TEST_CASE("Edge: Extremely long SQL (1MB)", "[edge][parser]") {
    PgSqlParser parser;

    // Build a ~1MB SQL string
    std::string sql = "SELECT * FROM users WHERE id = 1";
    while (sql.size() < 1024 * 1024) {
        sql += " OR id = " + std::to_string(sql.size());
    }

    // Should not crash — may fail to parse (libpg_query has limits)
    auto result = parser.parse(sql);
    // Just verify no crash — success or failure is acceptable
    (void)result;
    REQUIRE(true);
}

TEST_CASE("Edge: Pipeline with unknown user (default deny)", "[edge][pipeline]") {
    // Policy only allows user "alice"
    Policy p;
    p.name = "allow_alice_only";
    p.priority = 50;
    p.action = Decision::ALLOW;
    p.users.insert("alice");
    p.scope.table = "users";
    p.scope.operations = {StatementType::SELECT};

    auto rl_config = make_stress_rl_config();
    TestPipeline tp({p}, rl_config);

    auto req = make_request("unknown_user_xyz", "SELECT * FROM users WHERE id = 1");
    auto resp = tp.pipeline->execute(req);

    REQUIRE_FALSE(resp.success);
    REQUIRE(resp.error_code == ErrorCode::ACCESS_DENIED);
    tp.audit->shutdown();
}

TEST_CASE("Edge: Pipeline with user having no roles", "[edge][pipeline]") {
    // Role-only policy
    Policy p;
    p.name = "admin_only";
    p.priority = 50;
    p.action = Decision::ALLOW;
    p.roles.insert("admin");
    p.scope.table = "users";
    p.scope.operations = {StatementType::SELECT};

    auto rl_config = make_stress_rl_config();
    TestPipeline tp({p}, rl_config);

    // User with empty roles
    auto req = make_request("bob", "SELECT * FROM users WHERE id = 1", "testdb", {});
    auto resp = tp.pipeline->execute(req);

    REQUIRE_FALSE(resp.success);
    REQUIRE(resp.error_code == ErrorCode::ACCESS_DENIED);
    tp.audit->shutdown();
}

TEST_CASE("Edge: SQL injection attempts", "[edge][parser]") {
    PgSqlParser parser;

    SECTION("Multi-statement injection") {
        auto result = parser.parse("SELECT * FROM users; DROP TABLE users; --");
        // Should parse first statement or reject — no crash
        (void)result;
        REQUIRE(true);
    }

    SECTION("Classic OR injection") {
        auto result = parser.parse("SELECT * FROM users WHERE name = '' OR '1'='1'");
        // Valid SQL — should parse successfully
        REQUIRE(result.success);
    }

    SECTION("Nested block comment") {
        auto result = parser.parse("SELECT * FROM users WHERE id = 1 /* comment /* nested */ */");
        (void)result;
        REQUIRE(true);
    }

    SECTION("Escaped quote") {
        auto result = parser.parse("SELECT * FROM users WHERE name = 'O''Brien'");
        REQUIRE(result.success);
    }

    SECTION("Hex escape") {
        auto result = parser.parse("SELECT * FROM users WHERE name = E'\\x27'");
        (void)result;
        REQUIRE(true);
    }
}

TEST_CASE("Edge: Unicode in SQL", "[edge][parser]") {
    PgSqlParser parser;

    SECTION("UTF-8 accented characters in value") {
        auto result = parser.parse("SELECT * FROM users WHERE name = '\xC3\xA9\xC3\xA0\xC3\xBC'");
        REQUIRE(result.success);
    }

    SECTION("Quoted identifier with unicode") {
        auto result = parser.parse("SELECT * FROM \"utilisateurs\" WHERE \"nom\" = 'test'");
        REQUIRE(result.success);
    }
}

TEST_CASE("Edge: Concurrent rate limit check + reset_all", "[edge][rate_limiter]") {
    auto cfg = make_stress_rl_config(/*global_tps=*/100, /*global_burst=*/50);
    HierarchicalRateLimiter limiter(cfg);

    constexpr int num_checkers = 4;
    std::atomic<bool> stop{false};
    std::atomic<uint64_t> total_checks{0};

    std::vector<std::thread> checkers;
    for (int i = 0; i < num_checkers; ++i) {
        checkers.emplace_back([&, i] {
            std::string user = "user_" + std::to_string(i);
            while (!stop.load(std::memory_order_acquire)) {
                (void)limiter.check(user, "testdb");
                total_checks.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    // Reset thread
    std::thread resetter([&] {
        while (!stop.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            limiter.reset_all();
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    stop.store(true, std::memory_order_release);
    resetter.join();
    for (auto& c : checkers) c.join();

    REQUIRE(total_checks.load() > 0);
    // After reset, first check should be allowed
    auto result = limiter.check("fresh_user", "testdb");
    REQUIRE(result.allowed);
}

TEST_CASE("Edge: Policy evaluation with no policies loaded", "[edge][policy_engine]") {
    PolicyEngine engine;
    auto analysis = make_select_analysis("customers");

    auto result = engine.evaluate("user1", {"user"}, "testdb", analysis);
    REQUIRE(result.decision == Decision::BLOCK);
}

TEST_CASE("Edge: Very large number of policies (1000+)", "[edge][policy_engine]") {
    PolicyEngine engine;

    std::vector<Policy> policies;
    for (int i = 0; i < 1000; ++i) {
        Policy p;
        p.name = "allow_table_" + std::to_string(i);
        p.priority = 0;
        p.action = Decision::ALLOW;
        p.users.insert("*");
        p.scope.table = "table_" + std::to_string(i);
        p.scope.operations = {StatementType::SELECT};
        policies.push_back(p);
    }
    engine.load_policies(policies);

    REQUIRE(engine.policy_count() == 1000);

    // Evaluation on an existing table should ALLOW
    auto analysis_hit = make_select_analysis("table_500");
    auto result_hit = engine.evaluate("user1", {"user"}, "testdb", analysis_hit);
    REQUIRE(result_hit.decision == Decision::ALLOW);

    // Evaluation on a non-existent table should BLOCK (default deny)
    auto analysis_miss = make_select_analysis("nonexistent_table");
    auto result_miss = engine.evaluate("user1", {"user"}, "testdb", analysis_miss);
    REQUIRE(result_miss.decision == Decision::BLOCK);
}

TEST_CASE("Edge: Classifier with empty query result", "[edge][classifier]") {
    ClassifierRegistry classifier;

    QueryResult empty_result;
    empty_result.success = true;
    // Empty column_names and rows

    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;

    auto classification = classifier.classify(empty_result, analysis);
    REQUIRE(classification.classifications.empty());
}

TEST_CASE("Edge: Parse cache clear under concurrent access", "[edge][parse_cache]") {
    auto cache = std::make_shared<ParseCache>(1000, 8);
    auto parser = std::make_shared<PgSqlParser>(cache);

    constexpr int num_parsers = 4;
    std::atomic<bool> stop{false};
    std::atomic<uint64_t> parse_count{0};

    std::vector<std::thread> parsers_threads;
    for (int i = 0; i < num_parsers; ++i) {
        parsers_threads.emplace_back([&, i] {
            std::string sql = "SELECT * FROM t" + std::to_string(i) + " WHERE id = 1";
            while (!stop.load(std::memory_order_acquire)) {
                parser->parse(sql);
                parse_count.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    // Clearer thread
    std::thread clearer([&] {
        while (!stop.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            parser->clear_cache();
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    stop.store(true, std::memory_order_release);
    clearer.join();
    for (auto& t : parsers_threads) t.join();

    REQUIRE(parse_count.load() > 0);
}

// ============================================================================
// Category 7: Mixed Workload Simulation
// ============================================================================

TEST_CASE("Stress: Mixed workload 70/20/10 distribution with role-based policies", "[stress][mixed]") {
    // Build role-based policies
    std::vector<Policy> policies;

    // ALLOW SELECT for everyone
    {
        Policy p;
        p.name = "allow_select_all";
        p.priority = 50;
        p.action = Decision::ALLOW;
        p.users.insert("*");
        p.scope.table = "customers";
        p.scope.operations = {StatementType::SELECT};
        policies.push_back(p);
    }

    // ALLOW INSERT for readwrite and admin roles
    {
        Policy p;
        p.name = "allow_insert_rw";
        p.priority = 50;
        p.action = Decision::ALLOW;
        p.roles.insert("readwrite");
        p.roles.insert("admin");
        p.scope.table = "customers";
        p.scope.operations = {StatementType::INSERT, StatementType::UPDATE};
        policies.push_back(p);
    }

    // BLOCK DDL for everyone (explicit)
    {
        Policy p;
        p.name = "block_ddl";
        p.priority = 100;
        p.action = Decision::BLOCK;
        p.users.insert("*");
        p.scope.operations = {
            StatementType::CREATE_TABLE, StatementType::DROP_TABLE, StatementType::ALTER_TABLE};
        policies.push_back(p);
    }

    auto rl_config = make_stress_rl_config();
    TestPipeline tp(policies, rl_config);

    struct UserProfile {
        std::string name;
        std::vector<std::string> roles;
    };

    std::vector<UserProfile> profiles = {
        {"analyst", {"readonly"}},
        {"app_svc", {"readwrite"}},
        {"admin_user", {"admin"}}
    };

    struct ThreadStats {
        std::atomic<int> select_ok{0};
        std::atomic<int> select_fail{0};
        std::atomic<int> insert_ok{0};
        std::atomic<int> insert_fail{0};
        std::atomic<int> ddl_ok{0};
        std::atomic<int> ddl_fail{0};
        std::atomic<int> exceptions{0};
    };

    // Heap-allocate: atomics are non-movable, so std::vector won't work
    auto stats = std::make_unique<ThreadStats[]>(profiles.size());

    std::vector<std::thread> threads;
    for (size_t p = 0; p < profiles.size(); ++p) {
        threads.emplace_back([&, p] {
            auto& prof = profiles[p];
            auto& st = stats[p];
            std::mt19937 rng(42 + static_cast<unsigned>(p));
            std::uniform_int_distribution<int> dist(0, 99);

            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
            while (std::chrono::steady_clock::now() < deadline) {
                try {
                    int roll = dist(rng);
                    ProxyRequest req;

                    if (roll < 70) {
                        req = make_request(prof.name, "SELECT * FROM customers WHERE id = 1",
                                           "testdb", prof.roles);
                        auto resp = tp.pipeline->execute(req);
                        if (resp.success) st.select_ok.fetch_add(1);
                        else st.select_fail.fetch_add(1);
                    } else if (roll < 90) {
                        req = make_request(prof.name, "INSERT INTO customers (name) VALUES ('test')",
                                           "testdb", prof.roles);
                        auto resp = tp.pipeline->execute(req);
                        if (resp.success) st.insert_ok.fetch_add(1);
                        else st.insert_fail.fetch_add(1);
                    } else {
                        req = make_request(prof.name, "CREATE TABLE temp_test (id INT)",
                                           "testdb", prof.roles);
                        auto resp = tp.pipeline->execute(req);
                        if (resp.success) st.ddl_ok.fetch_add(1);
                        else st.ddl_fail.fetch_add(1);
                    }
                } catch (...) {
                    st.exceptions.fetch_add(1);
                }
            }
        });
    }

    for (auto& t : threads) t.join();
    tp.audit->shutdown();

    // Analyst (readonly): SELECT ok, INSERT blocked, DDL blocked
    REQUIRE(stats[0].exceptions.load() == 0);
    REQUIRE(stats[0].select_ok.load() > 0);
    REQUIRE(stats[0].insert_ok.load() == 0); // readonly can't insert
    REQUIRE(stats[0].ddl_ok.load() == 0);    // DDL blocked for everyone

    // App service (readwrite): SELECT ok, INSERT ok, DDL blocked
    REQUIRE(stats[1].exceptions.load() == 0);
    REQUIRE(stats[1].select_ok.load() > 0);
    REQUIRE(stats[1].insert_ok.load() > 0);  // readwrite can insert
    REQUIRE(stats[1].ddl_ok.load() == 0);    // DDL blocked

    // Admin: SELECT ok, INSERT ok, DDL blocked (explicit BLOCK policy)
    REQUIRE(stats[2].exceptions.load() == 0);
    REQUIRE(stats[2].select_ok.load() > 0);
    REQUIRE(stats[2].insert_ok.load() > 0);  // admin can insert
    REQUIRE(stats[2].ddl_ok.load() == 0);    // DDL blocked for everyone
}

TEST_CASE("Stress: Multi-user fairness under rate limiting", "[stress][mixed][fairness]") {
    // Shared global bottleneck
    auto cfg = make_stress_rl_config(
        /*global_tps=*/2000, /*global_burst=*/1000,
        /*user_tps=*/1000, /*user_burst=*/500,
        /*db_tps=*/100000, /*db_burst=*/100000,
        /*user_db_tps=*/100000, /*user_db_burst=*/100000);
    HierarchicalRateLimiter limiter(cfg);

    constexpr int num_users = 4;
    std::vector<uint64_t> per_user_allowed(num_users, 0);
    std::atomic<bool> go{false};

    std::vector<std::thread> threads;
    for (int i = 0; i < num_users; ++i) {
        threads.emplace_back([&, i] {
            while (!go.load(std::memory_order_acquire)) {}
            std::string user = "fair_user_" + std::to_string(i);
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
            while (std::chrono::steady_clock::now() < deadline) {
                auto result = limiter.check(user, "testdb");
                if (result.allowed) ++per_user_allowed[i];
            }
        });
    }

    go.store(true, std::memory_order_release);
    for (auto& t : threads) t.join();

    // No user should have zero allowed
    for (int i = 0; i < num_users; ++i) {
        REQUIRE(per_user_allowed[i] > 100);
    }

    // No user should dominate (>60% of total)
    uint64_t total = 0;
    for (int i = 0; i < num_users; ++i) total += per_user_allowed[i];
    for (int i = 0; i < num_users; ++i) {
        REQUIRE(per_user_allowed[i] < total * 6 / 10);
    }
}
