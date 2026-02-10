#include "core/pipeline.hpp"
#include "core/masking.hpp"
#include "core/query_rewriter.hpp"
#include "core/query_cost_estimator.hpp"
#include "core/utils.hpp"
#include "classifier/classifier_registry.hpp"
#include "audit/audit_emitter.hpp"
#include "db/database_router.hpp"
#include "security/sql_injection_detector.hpp"
#include "security/anomaly_detector.hpp"
#include "security/lineage_tracker.hpp"
#include "security/column_encryptor.hpp"
#include "schema/schema_manager.hpp"
#include "tenant/tenant_manager.hpp"
#include "tracing/trace_context.hpp"
#include "tracing/span.hpp"
#include "audit/audit_sampler.hpp"
#include "cache/result_cache.hpp"
#include "core/slow_query_tracker.hpp"
#include "executor/circuit_breaker.hpp"
#include "db/iconnection_pool.hpp"
#include "parser/parse_cache.hpp"
#include "server/adaptive_rate_controller.hpp"

#include <thread>
#include <unordered_set>

namespace sqlproxy {

Pipeline::Pipeline(PipelineComponents components)
    : c_(std::move(components)) {}

ProxyResponse Pipeline::execute(const ProxyRequest& request) {
    RequestContext ctx;
    ctx.request_id = request.request_id;
    ctx.user = request.user;
    ctx.roles = request.roles;
    ctx.database = request.database;
    ctx.sql = request.sql;
    ctx.source_ip = request.source_ip;
    ctx.user_attributes = request.user_attributes;
    ctx.tenant_id = request.tenant_id;
    ctx.dry_run = request.dry_run;
    ctx.priority = request.priority;

    // Distributed tracing: parse incoming traceparent or generate new context
    if (!request.traceparent.empty()) {
        const auto parsed = TraceContext::parse_traceparent(request.traceparent);
        if (parsed) {
            ctx.trace_context = *parsed;
        } else {
            ctx.trace_context = TraceContext::generate();
        }
    } else {
        ctx.trace_context = TraceContext::generate();
    }
    if (!request.tracestate.empty()) {
        ctx.trace_context.tracestate = request.tracestate;
    }

    // Tenant resolution: if multi-tenant enabled, override pipeline components
    // (policy_engine, rate_limiter, audit_emitter are swapped per-tenant)
    std::shared_ptr<PolicyEngine> active_policy_engine = c_.policy_engine;
    std::shared_ptr<IRateLimiter> active_rate_limiter = c_.rate_limiter;
    std::shared_ptr<AuditEmitter> active_audit_emitter = c_.audit_emitter;

    if (c_.tenant_manager && !ctx.tenant_id.empty()) {
        const auto tenant_ctx = c_.tenant_manager->resolve(ctx.tenant_id);
        if (tenant_ctx) {
            if (tenant_ctx->policy_engine) active_policy_engine = tenant_ctx->policy_engine;
            if (tenant_ctx->rate_limiter) active_rate_limiter = tenant_ctx->rate_limiter;
            if (tenant_ctx->audit_emitter) active_audit_emitter = tenant_ctx->audit_emitter;
        }
    }

    total_requests_.fetch_add(1, std::memory_order_relaxed);

    // Helper: emit audit and build response for blocked requests
    auto block_and_respond = [this](RequestContext& c) {
        requests_blocked_.fetch_add(1, std::memory_order_relaxed);
        emit_audit(c);
        return build_response(c);
    };

    // Layer 1: Rate limiting
    if (!check_rate_limit(ctx)) {
        return block_and_respond(ctx);
    }

    // Layer 2: Parse + Cache
    if (!parse_query(ctx)) {
        return block_and_respond(ctx);
    }

    // Layer 3: Analyze
    if (!analyze_query(ctx)) {
        return block_and_respond(ctx);
    }

    // Layer 2.5: Result cache lookup (only for SELECTs)
    if (c_.result_cache && c_.result_cache->is_enabled() &&
        ctx.analysis.statement_type == StatementType::SELECT &&
        ctx.fingerprint.has_value()) {
        const auto cached = c_.result_cache->get(
            ctx.fingerprint->hash, ctx.user, ctx.database);
        if (cached) {
            ctx.query_result = std::move(*cached);
            ctx.cache_hit = true;
            classify_results(ctx);
            record_lineage(ctx);
            emit_audit(ctx);
            return build_response(ctx);
        }
    }

    // Layer 3.5: SQL injection detection (can block)
    if (!check_injection(ctx)) {
        return block_and_respond(ctx);
    }

    // Layer 3.7: Anomaly detection (informational, never blocks)
    check_anomaly(ctx);

    // Layer 4: Policy evaluation (table-level)
    if (!evaluate_policy(ctx)) {
        return block_and_respond(ctx);
    }

    // Layer 4.1: Schema DDL interception (can block if approval required)
    if (!intercept_ddl(ctx)) {
        return block_and_respond(ctx);
    }

    // Layer 4.5: Query rewriting (RLS + enforce_limit)
    rewrite_query(ctx);

    // Layer 4.8: Query cost estimation (can block expensive queries)
    if (!check_query_cost(ctx)) {
        return block_and_respond(ctx);
    }

    // Dry-run mode: skip execution and everything after
    if (ctx.dry_run) {
        ctx.query_result.success = true;
        emit_audit(ctx);
        return build_response(ctx);
    }

    // Layer 5: Execute (with retry on transient failures)
    {
        bool exec_ok = execute_query(ctx);
        if (!exec_ok && retry_config_.enabled &&
            ctx.query_result.error_code == ErrorCode::DATABASE_ERROR) {
            int backoff_ms = retry_config_.initial_backoff_ms;
            for (int attempt = 0; attempt < retry_config_.max_retries; ++attempt) {
                std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms));
                ctx.query_result = {};
                exec_ok = execute_query(ctx);
                if (exec_ok) break;
                backoff_ms = std::min(backoff_ms * 2, retry_config_.max_backoff_ms);
            }
        }
        if (!exec_ok) {
            emit_audit(ctx);
            return build_response(ctx);
        }
    }

    // Report latency to adaptive rate controller
    if (c_.adaptive_rate_controller) {
        c_.adaptive_rate_controller->observe_latency(
            static_cast<uint64_t>(ctx.execution_time.count()));
    }

    // Layer 5.01: Slow query tracking
    if (c_.slow_query_tracker && c_.slow_query_tracker->is_enabled()) {
        SlowQueryRecord sq;
        sq.user = ctx.user;
        sq.database = ctx.database;
        sq.sql = ctx.sql;
        sq.execution_time = ctx.execution_time;
        sq.timestamp = ctx.received_at;
        sq.statement_type = ctx.analysis.statement_type;
        if (ctx.fingerprint.has_value()) {
            sq.fingerprint = ctx.fingerprint->normalized;
        }
        c_.slow_query_tracker->record_if_slow(sq);
    }

    // Layer 5.02: Parse cache DDL invalidation
    if (c_.parse_cache && ctx.query_result.success &&
        stmt_mask::test(ctx.analysis.statement_type, stmt_mask::kDDL) &&
        ctx.statement_info &&
        ctx.statement_info->parsed.ddl_object_name.has_value()) {
        c_.parse_cache->invalidate_table(*ctx.statement_info->parsed.ddl_object_name);
    }

    // Layer 5.05: Cache result (only for successful SELECTs)
    if (c_.result_cache && c_.result_cache->is_enabled() &&
        ctx.query_result.success &&
        ctx.analysis.statement_type == StatementType::SELECT &&
        ctx.fingerprint.has_value()) {
        c_.result_cache->put(ctx.fingerprint->hash, ctx.user, ctx.database,
                           ctx.query_result);
    }

    // Write-invalidation (clear cache for modified database)
    if (c_.result_cache && stmt_mask::test(ctx.analysis.statement_type, stmt_mask::kWrite | stmt_mask::kDDL)) {
        c_.result_cache->invalidate(ctx.database);
    }

    // Layer 5.1: Record DDL change (after successful execution)
    if (c_.schema_manager && stmt_mask::test(ctx.analysis.statement_type, stmt_mask::kDDL)) {
        std::string table_name;
        if (!ctx.analysis.source_tables.empty()) {
            table_name = ctx.analysis.source_tables[0].table;
        }
        c_.schema_manager->record_change(ctx.user, ctx.database, table_name,
            ctx.sql, ctx.analysis.statement_type);
    }

    // Layer 5.3: Decrypt encrypted columns (transparent)
    decrypt_columns(ctx);

    // Layer 5.5: Column-level ACL (remove blocked columns)
    apply_column_policies(ctx);

    // Layer 5.6: Data masking (mask values in-place)
    apply_masking(ctx);

    // Layer 6: Classify (runs on masked data — won't double-report PII)
    classify_results(ctx);

    // Layer 6.5: Record data lineage for PII columns
    record_lineage(ctx);

    // Build response first (response should not wait on audit I/O)
    auto response = build_response(ctx);

    // Layer 7: Audit (after response is ready — emit is non-blocking ring buffer push)
    emit_audit(ctx);

    return response;
}

bool Pipeline::check_rate_limit(RequestContext& ctx) {
    ScopedSpan span(ctx, "sql_proxy.rate_limit");
    const auto result = c_.rate_limiter->check(ctx.user, ctx.database);
    ctx.rate_limit_result = result;  // Always store for response headers
    if (!result.allowed) {
        ctx.rate_limited = true;
        ctx.query_result.success = false;
        ctx.query_result.error_code = ErrorCode::RATE_LIMITED;

        // Optimized string concatenation
        std::string msg;
        msg.reserve(16 + result.level.size() + 6);  // "Rate limited at " + level + " level"
        msg = "Rate limited at ";
        msg += result.level;
        msg += " level";
        ctx.query_result.error_message = std::move(msg);

        return false;
    }
    return true;
}

bool Pipeline::parse_query(RequestContext& ctx) {
    ScopedSpan span(ctx, "sql_proxy.parse");
    utils::Timer timer;

    // Resolve parser via router (per-database), fallback to default
    ISqlParser* active_parser = c_.parser.get();
    if (c_.router) {
        const auto routed = c_.router->get_parser(ctx.database);
        if (routed) active_parser = routed.get();
    }

    const auto parse_result = active_parser->parse(ctx.sql);
    ctx.parse_time = timer.elapsed_us();

    if (!parse_result.success) {
        ctx.query_result.success = false;
        ctx.query_result.error_code = ErrorCode::PARSE_ERROR;
        ctx.query_result.error_message = parse_result.error_message;
        return false;
    }

    ctx.statement_info = parse_result.statement_info;
    ctx.fingerprint = ctx.statement_info->fingerprint;
    return true;
}

bool Pipeline::analyze_query(RequestContext& ctx) {
    if (!ctx.statement_info) {
        return false;
    }

    ctx.analysis = SQLAnalyzer::analyze(
        ctx.statement_info->parsed,
        nullptr
    );

    return true;
}

bool Pipeline::evaluate_policy(RequestContext& ctx) {
    ScopedSpan span(ctx, "sql_proxy.policy");
    utils::Timer timer;

    ctx.policy_result = c_.policy_engine->evaluate(
        ctx.user,
        ctx.roles,
        ctx.database,
        ctx.analysis
    );

    ctx.policy_time = timer.elapsed_us();

    if (ctx.policy_result.decision != Decision::ALLOW) {
        ctx.query_result.success = false;
        ctx.query_result.error_code = ErrorCode::ACCESS_DENIED;
        ctx.query_result.error_message = ctx.policy_result.reason;
        return false;
    }

    return true;
}

void Pipeline::rewrite_query(RequestContext& ctx) {
    if (!c_.rewriter) return;

    std::string rewritten = c_.rewriter->rewrite(
        ctx.sql, ctx.user, ctx.roles, ctx.database,
        ctx.analysis, ctx.user_attributes);

    if (!rewritten.empty()) {
        ctx.original_sql = ctx.sql;
        ctx.sql = std::move(rewritten);
        ctx.sql_rewritten = true;
    }
}

bool Pipeline::execute_query(RequestContext& ctx) {
    ScopedSpan span(ctx, "sql_proxy.execute");
    // Resolve executor via router (per-database), fallback to default
    IQueryExecutor* exec = nullptr;
    if (c_.router) {
        const auto routed = c_.router->get_executor(ctx.database);
        if (routed) exec = routed.get();
    }
    if (!exec) exec = c_.executor.get();

    if (!exec) {
        // No executor configured - return mock success
        ctx.query_result.success = true;
        ctx.query_result.column_names = {"result"};
        ctx.query_result.rows = {{"mock_data"}};
        return true;
    }

    utils::Timer timer;

    ctx.query_result = exec->execute(ctx.sql, ctx.analysis.statement_type);
    ctx.execution_time = timer.elapsed_us();

    return ctx.query_result.success;
}

void Pipeline::apply_column_policies(RequestContext& ctx) {
    if (!ctx.query_result.success || ctx.query_result.column_names.empty()) return;

    utils::Timer timer;

    ctx.column_decisions = c_.policy_engine->evaluate_columns(
        ctx.user, ctx.roles, ctx.database, ctx.analysis,
        ctx.query_result.column_names);

    ctx.column_policy_time = timer.elapsed_us();

    // Find blocked column indices
    std::unordered_set<size_t> blocked_indices;
    for (size_t i = 0; i < ctx.column_decisions.size(); ++i) {
        if (ctx.column_decisions[i].decision == Decision::BLOCK) {
            blocked_indices.insert(i);
        }
    }

    if (blocked_indices.empty()) return;

    // Rebuild column_names, column_type_oids, and rows without blocked columns
    std::vector<std::string> new_columns;
    std::vector<uint32_t> new_type_oids;
    new_columns.reserve(ctx.query_result.column_names.size() - blocked_indices.size());
    new_type_oids.reserve(new_columns.capacity());

    for (size_t i = 0; i < ctx.query_result.column_names.size(); ++i) {
        if (!blocked_indices.contains(i)) {
            new_columns.emplace_back(std::move(ctx.query_result.column_names[i]));
            if (i < ctx.query_result.column_type_oids.size()) {
                new_type_oids.push_back(ctx.query_result.column_type_oids[i]);
            }
        }
    }

    // Rebuild each row
    for (auto& row : ctx.query_result.rows) {
        std::vector<std::string> new_row;
        new_row.reserve(new_columns.size());
        for (size_t i = 0; i < row.size(); ++i) {
            if (!blocked_indices.contains(i)) {
                new_row.emplace_back(std::move(row[i]));
            }
        }
        row = std::move(new_row);
    }

    ctx.query_result.column_names = std::move(new_columns);
    ctx.query_result.column_type_oids = std::move(new_type_oids);

    // Also rebuild column_decisions to remove blocked entries
    // (masking layer only sees the surviving columns)
    std::vector<ColumnPolicyDecision> surviving;
    surviving.reserve(ctx.column_decisions.size() - blocked_indices.size());
    for (size_t i = 0; i < ctx.column_decisions.size(); ++i) {
        if (!blocked_indices.contains(i)) {
            surviving.emplace_back(std::move(ctx.column_decisions[i]));
        }
    }
    ctx.column_decisions = std::move(surviving);
}

void Pipeline::apply_masking(RequestContext& ctx) {
    ScopedSpan span(ctx, "sql_proxy.mask");
    if (!ctx.query_result.success || ctx.column_decisions.empty()) return;

    utils::Timer timer;

    ctx.masking_applied = MaskingEngine::apply(ctx.query_result, ctx.column_decisions);

    ctx.masking_time = timer.elapsed_us();
}

void Pipeline::classify_results(RequestContext& ctx) {
    ScopedSpan span(ctx, "sql_proxy.classify");
    if (!c_.classifier || !ctx.query_result.success) {
        return;
    }

    utils::Timer timer;

    ctx.classification_result = c_.classifier->classify(
        ctx.query_result,
        ctx.analysis
    );

    ctx.classification_time = timer.elapsed_us();
}

namespace {

AuditRecord build_audit_record(const RequestContext& ctx) {
    AuditRecord r;

    // Tracing
    r.trace_id = ctx.trace_context.trace_id;
    r.span_id = ctx.trace_context.span_id;
    r.parent_span_id = ctx.trace_context.parent_span_id;

    // Request context
    r.timestamp = ctx.received_at;
    r.user = ctx.user;
    r.source_ip = ctx.source_ip;
    r.database_name = ctx.database;
    r.sql = ctx.sql;

    // Fingerprint
    if (ctx.fingerprint.has_value()) {
        r.fingerprint.hash = ctx.fingerprint->hash;
        r.fingerprint.normalized = ctx.fingerprint->normalized;
    }

    // Statement type
    if (ctx.statement_info) {
        r.statement_type = ctx.statement_info->parsed.type;
    }

    // Policy
    r.decision = ctx.rate_limited ? Decision::BLOCK : ctx.policy_result.decision;
    r.matched_policy = ctx.policy_result.matched_policy;
    r.block_reason = ctx.policy_result.reason;
    r.shadow_blocked = ctx.policy_result.shadow_blocked;
    r.shadow_policy = ctx.policy_result.shadow_policy;

    // Execution
    r.execution_success = ctx.query_result.success;
    r.error_code = ctx.query_result.error_code;
    r.error_message = ctx.query_result.error_message;
    r.rows_returned = ctx.query_result.rows.size();

    // Classification
    r.detected_classifications = ctx.classification_result.get_classified_types();

    // Performance
    r.parse_time = ctx.parse_time;
    r.policy_time = ctx.policy_time;
    r.execution_time = ctx.execution_time;
    r.classification_time = ctx.classification_time;
    const auto elapsed = std::chrono::steady_clock::now() - ctx.started_at;
    r.total_duration = std::chrono::duration_cast<std::chrono::microseconds>(elapsed);

    // Operational
    r.rate_limited = ctx.rate_limited;
    r.cache_hit = ctx.cache_hit;

    // Masking / query rewriting
    for (const auto& m : ctx.masking_applied) {
        r.masked_columns.push_back(m.column_name);
    }
    r.sql_rewritten = ctx.sql_rewritten;
    if (ctx.sql_rewritten) {
        r.original_sql = ctx.original_sql;
    }

    // Security
    r.threat_level = ctx.injection_result.threat_level;
    r.injection_patterns = ctx.injection_result.patterns_matched;
    r.injection_blocked = ctx.injection_result.should_block;
    r.anomaly_score = ctx.anomaly_result.anomaly_score;
    r.anomalies = ctx.anomaly_result.anomalies;

    // Spans
    for (const auto& s : ctx.spans) {
        r.spans.push_back({s.span_id, s.operation, s.duration_us()});
    }

    // Priority
    r.priority = ctx.priority;

    return r;
}

} // anonymous namespace

void Pipeline::emit_audit(const RequestContext& ctx) {
    if (!c_.audit_emitter) return;

    // Audit sampling check (before building the record)
    if (c_.audit_sampler && c_.audit_sampler->is_enabled()) {
        const uint64_t fp = ctx.fingerprint.has_value() ? ctx.fingerprint->hash : 0;
        const auto st = ctx.statement_info
            ? ctx.statement_info->parsed.type : StatementType::UNKNOWN;
        const auto decision = ctx.rate_limited ? Decision::BLOCK : ctx.policy_result.decision;
        if (!c_.audit_sampler->should_sample(st, decision, ctx.query_result.error_code, fp)) {
            return;
        }
    }

    c_.audit_emitter->emit(build_audit_record(ctx));
}

ProxyResponse Pipeline::build_response(const RequestContext& ctx) {
    ProxyResponse response;
    response.request_id = ctx.request_id;
    response.success = ctx.query_result.success;
    response.error_code = ctx.query_result.error_code;
    response.error_message = ctx.query_result.error_message;

    if (ctx.query_result.success) {
        response.result = ctx.query_result;
    }

    // Add classifications
    for (const auto& [col, cls] : ctx.classification_result.classifications) {
        response.classifications[col] = cls.type_string();
    }

    const auto elapsed = std::chrono::steady_clock::now() - ctx.started_at;
    response.execution_time_ms = std::chrono::duration_cast<std::chrono::microseconds>(elapsed);

    // Propagate trace context
    response.traceparent = ctx.trace_context.to_traceparent();

    response.policy_decision = ctx.policy_result.decision;
    response.matched_policy = ctx.policy_result.matched_policy;
    response.shadow_blocked = ctx.policy_result.shadow_blocked;
    response.shadow_policy = ctx.policy_result.shadow_policy;

    // Rate limit info for response headers
    response.rate_limit_info = ctx.rate_limit_result;

    // Column-level metadata
    for (const auto& m : ctx.masking_applied) {
        response.masked_columns.push_back(m.column_name);
    }
    for (const auto& d : ctx.column_decisions) {
        if (d.decision == Decision::BLOCK) {
            response.blocked_columns.push_back(d.column_name);
        }
    }

    return response;
}

bool Pipeline::check_injection(RequestContext& ctx) {
    if (!c_.injection_detector) return true;

    utils::Timer timer;

    std::string normalized;
    if (ctx.fingerprint.has_value()) {
        normalized = ctx.fingerprint->normalized;
    }

    ctx.injection_result = c_.injection_detector->analyze(
        ctx.sql, normalized, ctx.statement_info->parsed);

    ctx.injection_check_time = timer.elapsed_us();

    if (ctx.injection_result.should_block) {
        ctx.query_result.success = false;
        ctx.query_result.error_code = ErrorCode::SQLI_BLOCKED;
        ctx.query_result.error_message = ctx.injection_result.description;
        return false;
    }
    return true;
}

void Pipeline::check_anomaly(RequestContext& ctx) {
    if (!c_.anomaly_detector) return;

    // Collect table names from analysis
    std::vector<std::string> tables;
    tables.reserve(ctx.analysis.source_tables.size());
    for (const auto& t : ctx.analysis.source_tables) {
        tables.push_back(t.table);
    }

    const uint64_t fp_hash = ctx.fingerprint.has_value() ? ctx.fingerprint->hash : 0;

    // Check for anomalies (read-only scoring)
    ctx.anomaly_result = c_.anomaly_detector->check(ctx.user, tables, fp_hash);

    // Record this query in the user's profile (updates state)
    c_.anomaly_detector->record(ctx.user, tables, fp_hash);
}

void Pipeline::decrypt_columns(RequestContext& ctx) {
    if (!c_.column_encryptor || !c_.column_encryptor->is_enabled()) return;
    if (!ctx.query_result.success || ctx.query_result.rows.empty()) return;

    c_.column_encryptor->decrypt_result(ctx.query_result, ctx.database, ctx.analysis);
}

void Pipeline::record_lineage(RequestContext& ctx) {
    if (!c_.lineage_tracker) return;
    if (!ctx.query_result.success) return;

    // Record lineage for each classified column
    for (const auto& [col_name, classification] : ctx.classification_result.classifications) {
        LineageEvent event;
        event.timestamp = utils::format_timestamp(ctx.received_at);
        event.user = ctx.user;
        event.database = ctx.database;
        event.column = col_name;
        event.classification = classification.type_string();
        event.access_type = "SELECT";

        // Find the table for this column from analysis
        if (!ctx.analysis.source_tables.empty()) {
            event.table = ctx.analysis.source_tables[0].table;
        }

        // Check if the column was masked
        event.was_masked = false;
        for (const auto& m : ctx.masking_applied) {
            if (m.column_name == col_name) {
                event.was_masked = true;
                event.masking_action = masking_action_to_string(m.action);
                break;
            }
        }

        if (ctx.fingerprint.has_value()) {
            event.query_fingerprint = ctx.fingerprint->normalized;
        }

        c_.lineage_tracker->record(event);
    }
}

bool Pipeline::intercept_ddl(RequestContext& ctx) {
    if (!c_.schema_manager) return true;
    if (!ctx.statement_info) return true;

    // Only intercept DDL statements
    if (!stmt_mask::test(ctx.analysis.statement_type, stmt_mask::kDDL)) return true;

    const bool allowed = c_.schema_manager->intercept_ddl(
        ctx.user, ctx.database, ctx.sql, ctx.analysis.statement_type);

    if (!allowed) {
        ctx.ddl_requires_approval = true;
        ctx.query_result.success = false;
        ctx.query_result.error_code = ErrorCode::ACCESS_DENIED;
        ctx.query_result.error_message = "DDL requires approval — submitted for review";
        return false;
    }
    return true;
}

bool Pipeline::check_query_cost(RequestContext& ctx) {
    if (!c_.query_cost_estimator || !c_.query_cost_estimator->is_enabled()) return true;

    // Only check cost for SELECT statements
    if (ctx.analysis.statement_type != StatementType::SELECT) return true;

    const auto estimate = c_.query_cost_estimator->estimate(ctx.sql);
    if (estimate.is_rejected()) {
        ctx.query_result.success = false;
        ctx.query_result.error_code = ErrorCode::QUERY_TOO_EXPENSIVE;
        ctx.query_result.error_message = std::format(
            "Query too expensive: cost={:.1f} rows={} plan={}",
            estimate.total_cost, estimate.estimated_rows, estimate.plan_type);
        return false;
    }
    return true;
}

} // namespace sqlproxy
