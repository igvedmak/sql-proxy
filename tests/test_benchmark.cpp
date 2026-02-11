#include <benchmark/benchmark.h>

#include "parser/fingerprinter.hpp"
#include "parser/parse_cache.hpp"
#include "db/postgresql/pg_sql_parser.hpp"
#include "server/rate_limiter.hpp"
#include "policy/policy_engine.hpp"
#include "classifier/classifier_registry.hpp"
#include "audit/audit_emitter.hpp"
#include "core/pipeline.hpp"
#include "core/masking.hpp"
#include "core/query_rewriter.hpp"
#include "cache/result_cache.hpp"
#include "policy/policy_types.hpp"
#include "security/sql_injection_detector.hpp"
#include "security/anomaly_detector.hpp"
#include "executor/circuit_breaker.hpp"
#include "db/iquery_executor.hpp"
#include "analyzer/sql_analyzer.hpp"

#include <memory>
#include <mutex>
#include <string>
#include <vector>

using namespace sqlproxy;

// ============================================================================
// Helpers (same patterns as test_stress.cpp, separate compilation unit)
// ============================================================================

namespace {

// SQL queries of varying complexity for parameterized benchmarks
const std::string kSimpleSelect =
    "SELECT id, name FROM users WHERE id = 1";
const std::string kMediumSelect =
    "SELECT u.id, u.name, o.total FROM users u "
    "JOIN orders o ON u.id = o.user_id "
    "WHERE u.status = 'active' AND o.created_at > '2024-01-01'";
const std::string kComplexJoin =
    "SELECT u.id, u.name, o.total, oi.product_name, oi.quantity "
    "FROM users u "
    "JOIN orders o ON u.id = o.user_id "
    "JOIN order_items oi ON o.id = oi.order_id "
    "WHERE u.status = 'active' AND o.total > 100.00 "
    "GROUP BY u.id, u.name, o.total, oi.product_name, oi.quantity "
    "HAVING COUNT(*) > 1 ORDER BY o.total DESC LIMIT 50";
const std::string kSubquery =
    "SELECT * FROM users WHERE id IN "
    "(SELECT user_id FROM orders WHERE total > "
    "(SELECT AVG(total) FROM orders))";
const std::string kLargeInList =
    "SELECT * FROM users WHERE id IN "
    "(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,"
    "21,22,23,24,25,26,27,28,29,30)";

const std::vector<std::string> kQueryComplexities = {
    kSimpleSelect, kMediumSelect, kComplexJoin, kSubquery, kLargeInList
};

class MockExecutor : public IQueryExecutor {
public:
    QueryResult execute(const std::string& /*sql*/, StatementType /*stmt_type*/) override {
        QueryResult result;
        result.success = true;
        result.column_names = {"id", "name", "email"};
        result.column_type_oids = {23, 25, 25};
        result.rows = {
            {"1", "Alice", "alice@example.com"},
            {"2", "Bob", "bob@test.org"}
        };
        result.affected_rows = 0;
        result.execution_time = std::chrono::microseconds(100);
        return result;
    }
};

ProxyRequest make_request(
    const std::string& user,
    const std::string& sql,
    const std::string& database = "testdb",
    const std::vector<std::string>& roles = {"user"})
{
    static std::atomic<uint64_t> counter{0};
    ProxyRequest req;
    req.request_id = "bench-" + std::to_string(counter.fetch_add(1));
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
                         const std::string& table = "") {
    Policy p;
    p.name = name;
    p.priority = 0;
    p.action = Decision::ALLOW;
    p.users.insert("*");
    if (!table.empty()) p.scope.table = table;
    p.scope.operations = {
        StatementType::SELECT, StatementType::INSERT,
        StatementType::UPDATE, StatementType::DELETE
    };
    return p;
}

AnalysisResult make_select_analysis(const std::string& table) {
    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    analysis.sub_type = "SELECT";
    TableRef ref;
    ref.table = table;
    analysis.source_tables.push_back(ref);
    analysis.table_usage[ref.full_name()] = TableUsage::READ;
    return analysis;
}

HierarchicalRateLimiter::Config make_rl_config(
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

QueryResult make_query_result(size_t num_rows, size_t num_cols) {
    QueryResult result;
    result.success = true;
    for (size_t c = 0; c < num_cols; ++c) {
        result.column_names.push_back("col_" + std::to_string(c));
        result.column_type_oids.push_back(25); // TEXT
    }
    for (size_t r = 0; r < num_rows; ++r) {
        std::vector<std::string> row;
        row.reserve(num_cols);
        for (size_t c = 0; c < num_cols; ++c) {
            row.push_back("value_" + std::to_string(r) + "_" + std::to_string(c));
        }
        result.rows.push_back(std::move(row));
    }
    return result;
}

QueryResult make_pii_query_result(size_t num_rows) {
    QueryResult result;
    result.success = true;
    result.column_names = {"id", "email", "phone"};
    result.column_type_oids = {23, 25, 25};
    for (size_t r = 0; r < num_rows; ++r) {
        result.rows.push_back({
            std::to_string(r),
            "user" + std::to_string(r) + "@example.com",
            "555-012-" + std::to_string(1000 + r)
        });
    }
    return result;
}

std::vector<Policy> make_policies(size_t count) {
    std::vector<Policy> policies;
    policies.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        policies.push_back(make_allow_policy(
            "policy_" + std::to_string(i),
            "table_" + std::to_string(i)));
    }
    return policies;
}

// Pipeline wrapper for benchmark fixtures
struct BenchPipeline {
    std::shared_ptr<ParseCache> cache;
    std::shared_ptr<PgSqlParser> parser;
    std::shared_ptr<PolicyEngine> policy_engine;
    std::shared_ptr<HierarchicalRateLimiter> rate_limiter;
    std::shared_ptr<MockExecutor> executor;
    std::shared_ptr<ClassifierRegistry> classifier;
    std::shared_ptr<AuditEmitter> audit;
    std::shared_ptr<Pipeline> pipeline;

    BenchPipeline(const std::vector<Policy>& policies,
                  const HierarchicalRateLimiter::Config& rl_config)
    {
        cache = std::make_shared<ParseCache>(100000, 16);
        parser = std::make_shared<PgSqlParser>(cache);
        policy_engine = std::make_shared<PolicyEngine>();
        policy_engine->load_policies(policies);
        rate_limiter = std::make_shared<HierarchicalRateLimiter>(rl_config);
        executor = std::make_shared<MockExecutor>();
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

    ~BenchPipeline() { audit->shutdown(); }
};

} // anonymous namespace

// ============================================================================
// Category A: Micro Benchmarks — Single-threaded baseline latency
// ============================================================================

// A1: Fingerprint simple query
static void BM_Fingerprint_Simple(benchmark::State& state) {
    for (auto _ : state) {
        auto fp = QueryFingerprinter::fingerprint(kSimpleSelect);
        benchmark::DoNotOptimize(fp);
    }
}
BENCHMARK(BM_Fingerprint_Simple);

// A2: Fingerprint complex query
static void BM_Fingerprint_Complex(benchmark::State& state) {
    for (auto _ : state) {
        auto fp = QueryFingerprinter::fingerprint(kComplexJoin);
        benchmark::DoNotOptimize(fp);
    }
}
BENCHMARK(BM_Fingerprint_Complex);

// A3: Parser cache miss (unique queries each iteration)
static void BM_Parser_CacheMiss(benchmark::State& state) {
    auto cache = std::make_shared<ParseCache>(100000, 16);
    auto parser = std::make_shared<PgSqlParser>(cache);
    int i = 0;
    for (auto _ : state) {
        std::string sql = "SELECT * FROM bench_t_" + std::to_string(i++) + " WHERE id = 1";
        auto result = parser->parse(sql);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_Parser_CacheMiss);

// A4: Parser cache hit (same query, warm cache)
static void BM_Parser_CacheHit(benchmark::State& state) {
    auto cache = std::make_shared<ParseCache>(10000, 16);
    auto parser = std::make_shared<PgSqlParser>(cache);
    parser->parse(kSimpleSelect); // warm cache
    for (auto _ : state) {
        auto result = parser->parse(kSimpleSelect);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_Parser_CacheHit);

// A5: ParseCache::get() hit
static void BM_ParseCache_Get_Hit(benchmark::State& state) {
    auto cache = std::make_shared<ParseCache>(10000, 16);
    auto fp = QueryFingerprinter::fingerprint(kSimpleSelect);
    auto info = std::make_shared<StatementInfo>();
    info->fingerprint = fp;
    cache->put(info);
    for (auto _ : state) {
        auto result = cache->get(fp);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_ParseCache_Get_Hit);

// A6: ParseCache::get() miss
static void BM_ParseCache_Get_Miss(benchmark::State& state) {
    auto cache = std::make_shared<ParseCache>(10000, 16);
    auto fp = QueryFingerprinter::fingerprint("SELECT * FROM nonexistent_xyz");
    for (auto _ : state) {
        auto result = cache->get(fp);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_ParseCache_Get_Miss);

// A7: Rate limiter 4-level check (all pass)
static void BM_RateLimiter_Check(benchmark::State& state) {
    auto cfg = make_rl_config();
    HierarchicalRateLimiter limiter(cfg);
    for (auto _ : state) {
        auto result = limiter.check("bench_user", "bench_db");
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_RateLimiter_Check);

// A8: Policy engine evaluate — hit
static void BM_PolicyEngine_Hit(benchmark::State& state) {
    PolicyEngine engine;
    auto policies = make_policies(10);
    engine.load_policies(policies);
    auto analysis = make_select_analysis("table_5");
    for (auto _ : state) {
        auto result = engine.evaluate("user1", {"user"}, "testdb", analysis);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_PolicyEngine_Hit);

// A9: Policy engine evaluate — miss (default deny)
static void BM_PolicyEngine_Miss(benchmark::State& state) {
    PolicyEngine engine;
    auto policies = make_policies(10);
    engine.load_policies(policies);
    auto analysis = make_select_analysis("nonexistent_table");
    for (auto _ : state) {
        auto result = engine.evaluate("user1", {"user"}, "testdb", analysis);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_PolicyEngine_Miss);

// A10: Classifier by column name (fast path)
static void BM_Classifier_ByName(benchmark::State& state) {
    ClassifierRegistry classifier;
    auto result = make_pii_query_result(2);
    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    for (auto _ : state) {
        auto cls = classifier.classify(result, analysis);
        benchmark::DoNotOptimize(cls);
    }
}
BENCHMARK(BM_Classifier_ByName);

// A11: Classifier by regex (slow path — unknown column names, email values)
static void BM_Classifier_ByRegex(benchmark::State& state) {
    ClassifierRegistry classifier;
    QueryResult result;
    result.success = true;
    result.column_names = {"id", "data_field"};
    result.column_type_oids = {23, 25};
    for (int r = 0; r < 20; ++r) {
        result.rows.push_back({
            std::to_string(r),
            "user" + std::to_string(r) + "@example.com"
        });
    }
    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    for (auto _ : state) {
        auto cls = classifier.classify(result, analysis);
        benchmark::DoNotOptimize(cls);
    }
}
BENCHMARK(BM_Classifier_ByRegex);

// A12: Audit emitter emit (lock-free ring buffer push)
static void BM_AuditEmitter_Emit(benchmark::State& state) {
    auto audit = std::make_unique<AuditEmitter>("/dev/null");
    AuditRecord record;
    record.user = "bench_user";
    record.sql = "SELECT 1";
    record.statement_type = StatementType::SELECT;
    for (auto _ : state) {
        audit->emit(record);
    }
    state.SetItemsProcessed(state.iterations());
    audit->shutdown();
}
BENCHMARK(BM_AuditEmitter_Emit);

// ============================================================================
// Category B: Throughput Benchmarks — Multi-threaded
// ============================================================================

// B1: Rate limiter throughput under contention
static void BM_RateLimiter_Throughput(benchmark::State& state) {
    static auto cfg = make_rl_config();
    static HierarchicalRateLimiter limiter(cfg);
    std::string user = "user_" + std::to_string(state.thread_index());
    for (auto _ : state) {
        auto result = limiter.check(user, "bench_db");
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_RateLimiter_Throughput)->Threads(1)->Threads(2)->Threads(4)->Threads(8);

// B2: Parse cache throughput — same query (same shard contention)
static void BM_ParseCache_Throughput_SameQuery(benchmark::State& state) {
    static auto cache = std::make_shared<ParseCache>(10000, 16);
    static auto parser = std::make_shared<PgSqlParser>(cache);
    static std::once_flag warmup;
    std::call_once(warmup, [&] { parser->parse(kSimpleSelect); });
    for (auto _ : state) {
        auto result = parser->parse(kSimpleSelect);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_ParseCache_Throughput_SameQuery)->Threads(1)->Threads(2)->Threads(4)->Threads(8);

// B3: Parse cache throughput — different queries (cross-shard)
static void BM_ParseCache_Throughput_DiffQueries(benchmark::State& state) {
    static auto cache = std::make_shared<ParseCache>(10000, 16);
    static auto parser = std::make_shared<PgSqlParser>(cache);
    // Each thread uses a different query to hit different shards
    std::string sql = "SELECT * FROM thr_table_" + std::to_string(state.thread_index()) + " WHERE id = 1";
    // Warm
    parser->parse(sql);
    for (auto _ : state) {
        auto result = parser->parse(sql);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_ParseCache_Throughput_DiffQueries)->Threads(1)->Threads(2)->Threads(4)->Threads(8);

// B4: Policy engine throughput under contention
static void BM_PolicyEngine_Throughput(benchmark::State& state) {
    static PolicyEngine engine;
    static std::once_flag init;
    std::call_once(init, [] {
        engine.load_policies(make_policies(100));
    });
    auto analysis = make_select_analysis("table_50");
    for (auto _ : state) {
        auto result = engine.evaluate("user1", {"user"}, "testdb", analysis);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_PolicyEngine_Throughput)->Threads(1)->Threads(2)->Threads(4)->Threads(8);

// B5: Audit emitter throughput (ring buffer contention)
static void BM_AuditEmitter_Throughput(benchmark::State& state) {
    static auto audit = std::make_unique<AuditEmitter>("/dev/null");
    AuditRecord record;
    record.user = "bench_user_" + std::to_string(state.thread_index());
    record.sql = "SELECT 1";
    record.statement_type = StatementType::SELECT;
    for (auto _ : state) {
        audit->emit(record);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_AuditEmitter_Throughput)->Threads(1)->Threads(2)->Threads(4)->Threads(8);

// ============================================================================
// Category C: Pipeline Benchmarks — End-to-end
// ============================================================================

// C1: Full pipeline single-threaded (warm cache)
static void BM_Pipeline_SingleThread(benchmark::State& state) {
    std::vector<Policy> policies = {
        make_allow_policy("allow_users", "users"),
        make_allow_policy("allow_customers", "customers"),
        make_allow_policy("allow_orders", "orders")
    };
    BenchPipeline bp(policies, make_rl_config());

    // Warm cache
    auto warm_req = make_request("bench_user", "SELECT * FROM users WHERE id = 1");
    bp.pipeline->execute(warm_req);

    for (auto _ : state) {
        auto req = make_request("bench_user", "SELECT * FROM users WHERE id = 1");
        auto resp = bp.pipeline->execute(req);
        benchmark::DoNotOptimize(resp);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Pipeline_SingleThread);

// C2: Pipeline multi-threaded throughput
static void BM_Pipeline_MultiThread(benchmark::State& state) {
    static std::unique_ptr<BenchPipeline> bp;
    static std::once_flag init;
    std::call_once(init, [] {
        std::vector<Policy> policies = {
            make_allow_policy("allow_users", "users"),
            make_allow_policy("allow_customers", "customers"),
            make_allow_policy("allow_orders", "orders")
        };
        bp = std::make_unique<BenchPipeline>(policies, make_rl_config());
        // Warm cache
        auto req = make_request("warmup", "SELECT * FROM users WHERE id = 1");
        bp->pipeline->execute(req);
    });
    std::string user = "bench_user_" + std::to_string(state.thread_index());
    for (auto _ : state) {
        auto req = make_request(user, "SELECT * FROM users WHERE id = 1");
        auto resp = bp->pipeline->execute(req);
        benchmark::DoNotOptimize(resp);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Pipeline_MultiThread)->Threads(1)->Threads(2)->Threads(4)->Threads(8);

// C3: Pipeline cache hit (same query repeated)
static void BM_Pipeline_CacheHit(benchmark::State& state) {
    std::vector<Policy> policies = {make_allow_policy("allow_users", "users")};
    BenchPipeline bp(policies, make_rl_config());
    // Warm
    bp.pipeline->execute(make_request("bench_user", "SELECT * FROM users WHERE id = 1"));
    for (auto _ : state) {
        auto req = make_request("bench_user", "SELECT * FROM users WHERE id = 1");
        auto resp = bp.pipeline->execute(req);
        benchmark::DoNotOptimize(resp);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Pipeline_CacheHit);

// C4: Pipeline cache miss (unique queries force full parse)
static void BM_Pipeline_CacheMiss(benchmark::State& state) {
    std::vector<Policy> policies = {make_allow_policy("allow_all")};
    BenchPipeline bp(policies, make_rl_config());
    int i = 0;
    for (auto _ : state) {
        std::string sql = "SELECT * FROM bench_miss_" + std::to_string(i++) + " WHERE id = 1";
        auto req = make_request("bench_user", sql);
        auto resp = bp.pipeline->execute(req);
        benchmark::DoNotOptimize(resp);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Pipeline_CacheMiss);

// ============================================================================
// Category D: Scaling / Parameterized Benchmarks
// ============================================================================

// D1: Fingerprint scaling with query complexity
static void BM_Fingerprint_QueryComplexity(benchmark::State& state) {
    const auto& sql = kQueryComplexities[static_cast<size_t>(state.range(0))];
    for (auto _ : state) {
        auto fp = QueryFingerprinter::fingerprint(sql);
        benchmark::DoNotOptimize(fp);
    }
    state.SetLabel("len=" + std::to_string(sql.size()));
}
BENCHMARK(BM_Fingerprint_QueryComplexity)->DenseRange(0, 4);

// D2: Parser scaling with query complexity
static void BM_Parser_QueryComplexity(benchmark::State& state) {
    auto cache = std::make_shared<ParseCache>(10000, 16);
    auto parser = std::make_shared<PgSqlParser>(cache);
    const auto& sql = kQueryComplexities[static_cast<size_t>(state.range(0))];
    // Warm cache for this query
    parser->parse(sql);
    for (auto _ : state) {
        auto result = parser->parse(sql);
        benchmark::DoNotOptimize(result);
    }
    state.SetLabel("len=" + std::to_string(sql.size()));
}
BENCHMARK(BM_Parser_QueryComplexity)->DenseRange(0, 4);

// D3: Policy engine scaling with policy count
static void BM_PolicyEngine_PolicyCount(benchmark::State& state) {
    const auto policy_count = static_cast<size_t>(state.range(0));
    PolicyEngine engine;
    auto policies = make_policies(policy_count);
    // Add a target policy that will match
    policies.push_back(make_allow_policy("target_policy", "target_table"));
    engine.load_policies(policies);
    auto analysis = make_select_analysis("target_table");
    for (auto _ : state) {
        auto result = engine.evaluate("user1", {"user"}, "testdb", analysis);
        benchmark::DoNotOptimize(result);
    }
    state.SetLabel("policies=" + std::to_string(policy_count));
}
BENCHMARK(BM_PolicyEngine_PolicyCount)->Arg(1)->Arg(10)->Arg(100)->Arg(1000);

// D4: Classifier scaling with result set size (rows)
static void BM_Classifier_ResultSetSize(benchmark::State& state) {
    const auto num_rows = static_cast<size_t>(state.range(0));
    ClassifierRegistry classifier;
    auto result = make_pii_query_result(num_rows);
    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    for (auto _ : state) {
        auto cls = classifier.classify(result, analysis);
        benchmark::DoNotOptimize(cls);
    }
    state.SetLabel("rows=" + std::to_string(num_rows));
}
BENCHMARK(BM_Classifier_ResultSetSize)->Arg(1)->Arg(10)->Arg(100)->Arg(1000);

// D5: Classifier scaling with column count
static void BM_Classifier_ColumnCount(benchmark::State& state) {
    const auto num_cols = static_cast<size_t>(state.range(0));
    ClassifierRegistry classifier;
    auto result = make_query_result(10, num_cols);
    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    for (auto _ : state) {
        auto cls = classifier.classify(result, analysis);
        benchmark::DoNotOptimize(cls);
    }
    state.SetLabel("cols=" + std::to_string(num_cols));
}
BENCHMARK(BM_Classifier_ColumnCount)->Arg(1)->Arg(5)->Arg(10)->Arg(20)->Arg(50);

// D6: Parse cache scaling with shard count
static void BM_ParseCache_ShardCount(benchmark::State& state) {
    const auto num_shards = static_cast<size_t>(state.range(0));
    auto cache = std::make_shared<ParseCache>(10000, num_shards);
    auto parser = std::make_shared<PgSqlParser>(cache);
    // Warm
    parser->parse(kSimpleSelect);
    for (auto _ : state) {
        auto result = parser->parse(kSimpleSelect);
        benchmark::DoNotOptimize(result);
    }
    state.SetLabel("shards=" + std::to_string(num_shards));
}
BENCHMARK(BM_ParseCache_ShardCount)->Arg(1)->Arg(4)->Arg(8)->Arg(16)->Arg(32);

// D7: Rate limiter scaling with unique user count
static void BM_RateLimiter_UniqueUsers(benchmark::State& state) {
    const auto num_users = static_cast<size_t>(state.range(0));
    auto cfg = make_rl_config();
    HierarchicalRateLimiter limiter(cfg);

    // Pre-warm all user buckets
    for (size_t i = 0; i < num_users; ++i) {
        (void)limiter.check("user_" + std::to_string(i), "bench_db");
    }

    size_t user_idx = 0;
    for (auto _ : state) {
        std::string user = "user_" + std::to_string(user_idx % num_users);
        auto result = limiter.check(user, "bench_db");
        benchmark::DoNotOptimize(result);
        ++user_idx;
    }
    state.SetLabel("users=" + std::to_string(num_users));
}
BENCHMARK(BM_RateLimiter_UniqueUsers)->Arg(1)->Arg(10)->Arg(100)->Arg(1000);

// ============================================================================
// Category E: Result Cache Benchmarks
// ============================================================================

// E1: ResultCache get — hit
static void BM_ResultCache_Hit(benchmark::State& state) {
    ResultCache::Config cfg;
    cfg.enabled = true;
    cfg.max_entries = 10000;
    cfg.num_shards = 16;
    cfg.ttl = std::chrono::seconds(300);
    ResultCache cache(cfg);

    auto result = make_query_result(10, 3);
    cache.put(12345, "bench_user", "testdb", result);

    for (auto _ : state) {
        auto r = cache.get(12345, "bench_user", "testdb");
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_ResultCache_Hit);

// E2: ResultCache get — miss
static void BM_ResultCache_Miss(benchmark::State& state) {
    ResultCache::Config cfg;
    cfg.enabled = true;
    cfg.max_entries = 10000;
    cfg.num_shards = 16;
    ResultCache cache(cfg);

    for (auto _ : state) {
        auto r = cache.get(99999, "nobody", "nodb");
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_ResultCache_Miss);

// E3: ResultCache put
static void BM_ResultCache_Put(benchmark::State& state) {
    ResultCache::Config cfg;
    cfg.enabled = true;
    cfg.max_entries = 100000;
    cfg.num_shards = 16;
    ResultCache cache(cfg);
    auto result = make_query_result(5, 3);

    uint64_t i = 0;
    for (auto _ : state) {
        cache.put(i++, "bench_user", "testdb", result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_ResultCache_Put);

// E4: ResultCache invalidate
static void BM_ResultCache_Invalidate(benchmark::State& state) {
    ResultCache::Config cfg;
    cfg.enabled = true;
    cfg.max_entries = 10000;
    cfg.num_shards = 16;
    ResultCache cache(cfg);

    auto result = make_query_result(5, 3);
    for (uint64_t i = 0; i < 1000; ++i) {
        cache.put(i, "user", "testdb", result);
    }

    for (auto _ : state) {
        cache.invalidate("testdb");
        // Re-populate for next iteration
        state.PauseTiming();
        for (uint64_t i = 0; i < 1000; ++i) {
            cache.put(i, "user", "testdb", result);
        }
        state.ResumeTiming();
    }
}
BENCHMARK(BM_ResultCache_Invalidate);

// ============================================================================
// Category F: SQL Injection Detector Benchmarks
// ============================================================================

// F1: Benign query (no threats)
static void BM_SQLInjection_Benign(benchmark::State& state) {
    SqlInjectionDetector detector;
    ParsedQuery parsed;
    parsed.type = StatementType::SELECT;
    TableRef ref;
    ref.table = "users";
    parsed.tables.push_back(ref);

    for (auto _ : state) {
        auto r = detector.analyze(kSimpleSelect, kSimpleSelect, parsed);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_SQLInjection_Benign);

// F2: Tautology attack
static void BM_SQLInjection_Tautology(benchmark::State& state) {
    SqlInjectionDetector detector;
    const std::string sql = "SELECT * FROM users WHERE id = 1 OR 1=1";
    ParsedQuery parsed;
    parsed.type = StatementType::SELECT;
    TableRef ref;
    ref.table = "users";
    parsed.tables.push_back(ref);

    for (auto _ : state) {
        auto r = detector.analyze(sql, sql, parsed);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_SQLInjection_Tautology);

// F3: Union injection
static void BM_SQLInjection_Union(benchmark::State& state) {
    SqlInjectionDetector detector;
    const std::string sql =
        "SELECT id FROM users WHERE name = '' UNION SELECT password FROM admin --";
    ParsedQuery parsed;
    parsed.type = StatementType::SELECT;
    TableRef r1, r2;
    r1.table = "users";
    r2.table = "admin";
    parsed.tables.push_back(r1);
    parsed.tables.push_back(r2);

    for (auto _ : state) {
        auto r = detector.analyze(sql, sql, parsed);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_SQLInjection_Union);

// F4: Stacked queries
static void BM_SQLInjection_Stacked(benchmark::State& state) {
    SqlInjectionDetector detector;
    const std::string sql = "SELECT 1; DROP TABLE users; --";
    ParsedQuery parsed;
    parsed.type = StatementType::SELECT;

    for (auto _ : state) {
        auto r = detector.analyze(sql, sql, parsed);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_SQLInjection_Stacked);

// F5: Time-based blind
static void BM_SQLInjection_TimeBased(benchmark::State& state) {
    SqlInjectionDetector detector;
    const std::string sql =
        "SELECT * FROM users WHERE id = 1 AND pg_sleep(5)";
    ParsedQuery parsed;
    parsed.type = StatementType::SELECT;
    TableRef ref;
    ref.table = "users";
    parsed.tables.push_back(ref);

    for (auto _ : state) {
        auto r = detector.analyze(sql, sql, parsed);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_SQLInjection_TimeBased);

// ============================================================================
// Category G: Masking Engine Benchmarks
// ============================================================================

// G1: mask_value — REDACT
static void BM_Masking_Redact(benchmark::State& state) {
    for (auto _ : state) {
        auto r = MaskingEngine::mask_value("alice@example.com", MaskingAction::REDACT);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Masking_Redact);

// G2: mask_value — PARTIAL
static void BM_Masking_Partial(benchmark::State& state) {
    for (auto _ : state) {
        auto r = MaskingEngine::mask_value("alice@example.com", MaskingAction::PARTIAL, 3, 3);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Masking_Partial);

// G3: mask_value — HASH (SHA256)
static void BM_Masking_Hash(benchmark::State& state) {
    for (auto _ : state) {
        auto r = MaskingEngine::mask_value("alice@example.com", MaskingAction::HASH);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Masking_Hash);

// G4: mask_value — NULLIFY
static void BM_Masking_Nullify(benchmark::State& state) {
    for (auto _ : state) {
        auto r = MaskingEngine::mask_value("alice@example.com", MaskingAction::NULLIFY);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Masking_Nullify);

// G5: Masking apply — scaling with row count
static void BM_Masking_Apply(benchmark::State& state) {
    const auto num_rows = static_cast<size_t>(state.range(0));

    ColumnPolicyDecision d1;
    d1.column_name = "col_1";
    d1.decision = Decision::ALLOW;
    d1.masking = MaskingAction::REDACT;
    d1.matched_policy = "bench_policy";

    ColumnPolicyDecision d2;
    d2.column_name = "col_2";
    d2.decision = Decision::ALLOW;
    d2.masking = MaskingAction::HASH;
    d2.matched_policy = "bench_policy";

    std::vector<ColumnPolicyDecision> decisions = {d1, d2};

    for (auto _ : state) {
        state.PauseTiming();
        auto result = make_query_result(num_rows, 5);
        state.ResumeTiming();

        auto records = MaskingEngine::apply(result, decisions);
        benchmark::DoNotOptimize(records);
    }
    state.SetLabel("rows=" + std::to_string(num_rows));
}
BENCHMARK(BM_Masking_Apply)->Arg(10)->Arg(100)->Arg(1000)->Arg(5000)->Arg(10000);

// ============================================================================
// Category H: Anomaly Detector Benchmarks
// ============================================================================

// H1: check — new user (cold profile)
static void BM_AnomalyDetector_Check_Cold(benchmark::State& state) {
    AnomalyDetector detector;
    std::vector<std::string> tables = {"users"};
    int i = 0;
    for (auto _ : state) {
        auto r = detector.check("cold_user_" + std::to_string(i++), tables, 12345);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_AnomalyDetector_Check_Cold);

// H2: check — warm user (established profile)
static void BM_AnomalyDetector_Check_Warm(benchmark::State& state) {
    AnomalyDetector detector;
    std::vector<std::string> tables = {"users", "orders"};
    // Build profile
    for (int i = 0; i < 200; ++i) {
        detector.record("warm_user", tables, static_cast<uint64_t>(i));
    }
    for (auto _ : state) {
        auto r = detector.check("warm_user", tables, 12345);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_AnomalyDetector_Check_Warm);

// H3: record
static void BM_AnomalyDetector_Record(benchmark::State& state) {
    AnomalyDetector detector;
    std::vector<std::string> tables = {"users"};
    uint64_t fp = 0;
    for (auto _ : state) {
        detector.record("bench_user", tables, fp++);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_AnomalyDetector_Record);

// H4: Anomaly detector scaling with tracked users
static void BM_AnomalyDetector_UserScaling(benchmark::State& state) {
    const auto num_users = static_cast<size_t>(state.range(0));
    AnomalyDetector detector;
    std::vector<std::string> tables = {"users"};

    // Pre-populate user profiles
    for (size_t i = 0; i < num_users; ++i) {
        detector.record("user_" + std::to_string(i), tables, i);
    }

    size_t idx = 0;
    for (auto _ : state) {
        auto r = detector.check("user_" + std::to_string(idx % num_users), tables, 99);
        benchmark::DoNotOptimize(r);
        ++idx;
    }
    state.SetLabel("users=" + std::to_string(num_users));
}
BENCHMARK(BM_AnomalyDetector_UserScaling)->Arg(1)->Arg(10)->Arg(100)->Arg(1000);

// ============================================================================
// Category I: Circuit Breaker Benchmarks
// ============================================================================

// I1: allow_request — CLOSED state (happy path)
static void BM_CircuitBreaker_AllowClosed(benchmark::State& state) {
    CircuitBreaker cb("bench_cb");
    for (auto _ : state) {
        bool r = cb.allow_request();
        benchmark::DoNotOptimize(r);
        cb.record_success();
    }
}
BENCHMARK(BM_CircuitBreaker_AllowClosed);

// I2: allow_request — OPEN state (fast reject)
static void BM_CircuitBreaker_RejectOpen(benchmark::State& state) {
    CircuitBreaker::Config cfg;
    cfg.failure_threshold = 1;
    cfg.timeout = std::chrono::milliseconds(60000); // Long timeout so it stays open
    CircuitBreaker cb("bench_cb_open", cfg);

    // Trip the breaker
    cb.allow_request();
    cb.record_failure();

    for (auto _ : state) {
        bool r = cb.allow_request();
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_CircuitBreaker_RejectOpen);

// I3: record_success + record_failure cycle
static void BM_CircuitBreaker_RecordCycle(benchmark::State& state) {
    CircuitBreaker cb("bench_cb_cycle");
    for (auto _ : state) {
        cb.allow_request();
        cb.record_success();
        cb.allow_request();
        cb.record_failure(FailureCategory::TRANSIENT);
    }
    state.SetItemsProcessed(state.iterations() * 2);
}
BENCHMARK(BM_CircuitBreaker_RecordCycle);

// I4: get_stats
static void BM_CircuitBreaker_GetStats(benchmark::State& state) {
    CircuitBreaker cb("bench_cb_stats");
    for (int i = 0; i < 100; ++i) {
        cb.allow_request();
        cb.record_success();
    }
    for (auto _ : state) {
        auto s = cb.get_stats();
        benchmark::DoNotOptimize(s);
    }
}
BENCHMARK(BM_CircuitBreaker_GetStats);

// ============================================================================
// Category J: Query Rewriter Benchmarks
// ============================================================================

// J1: Rewrite with RLS injection
static void BM_QueryRewriter_RLS(benchmark::State& state) {
    QueryRewriter rewriter;
    RlsRule rule;
    rule.name = "tenant_isolation";
    rule.table = "orders";
    rule.condition = "tenant_id = '$USER'";
    rule.users = {"*"};
    rewriter.load_rules({rule}, {});

    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    TableRef ref;
    ref.table = "orders";
    analysis.source_tables.push_back(ref);
    analysis.table_usage["orders"] = TableUsage::READ;

    const std::string sql = "SELECT * FROM orders WHERE total > 100";
    std::unordered_map<std::string, std::string> attrs;

    for (auto _ : state) {
        auto r = rewriter.rewrite(sql, "alice", {"user"}, "testdb", analysis, attrs);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_QueryRewriter_RLS);

// J2: Rewrite with enforce_limit
static void BM_QueryRewriter_EnforceLimit(benchmark::State& state) {
    QueryRewriter rewriter;
    RewriteRule rule;
    rule.name = "enforce_limit";
    rule.type = "enforce_limit";
    rule.limit_value = 1000;
    rule.users = {"*"};
    rewriter.load_rules({}, {rule});

    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    TableRef ref;
    ref.table = "users";
    analysis.source_tables.push_back(ref);

    const std::string sql = "SELECT * FROM users WHERE active = true";
    std::unordered_map<std::string, std::string> attrs;

    for (auto _ : state) {
        auto r = rewriter.rewrite(sql, "alice", {"user"}, "testdb", analysis, attrs);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_QueryRewriter_EnforceLimit);

// J3: Rewrite — no matching rules (passthrough)
static void BM_QueryRewriter_NoMatch(benchmark::State& state) {
    QueryRewriter rewriter;
    RlsRule rule;
    rule.name = "other_table";
    rule.table = "orders";
    rule.condition = "tenant_id = '$USER'";
    rule.users = {"*"};
    rewriter.load_rules({rule}, {});

    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    TableRef ref;
    ref.table = "users";
    analysis.source_tables.push_back(ref);

    const std::string sql = "SELECT * FROM users WHERE id = 1";
    std::unordered_map<std::string, std::string> attrs;

    for (auto _ : state) {
        auto r = rewriter.rewrite(sql, "alice", {"user"}, "testdb", analysis, attrs);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_QueryRewriter_NoMatch);
