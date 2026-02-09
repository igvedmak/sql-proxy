#include "core/pipeline.hpp"
#include "core/masking.hpp"
#include "core/query_rewriter.hpp"
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
#include "audit/audit_sampler.hpp"
#include "cache/result_cache.hpp"
#include "core/slow_query_tracker.hpp"
#include "executor/circuit_breaker.hpp"
#include "db/iconnection_pool.hpp"
#include "parser/parse_cache.hpp"

#include <unordered_set>

namespace sqlproxy {

Pipeline::Pipeline(
    std::shared_ptr<ISqlParser> parser,
    std::shared_ptr<PolicyEngine> policy_engine,
    std::shared_ptr<IRateLimiter> rate_limiter,
    std::shared_ptr<IQueryExecutor> executor,
    std::shared_ptr<ClassifierRegistry> classifier,
    std::shared_ptr<AuditEmitter> audit_emitter,
    std::shared_ptr<QueryRewriter> rewriter,
    std::shared_ptr<DatabaseRouter> router,
    std::shared_ptr<PreparedStatementTracker> prepared,
    std::shared_ptr<SqlInjectionDetector> injection_detector,
    std::shared_ptr<AnomalyDetector> anomaly_detector,
    std::shared_ptr<LineageTracker> lineage_tracker,
    std::shared_ptr<ColumnEncryptor> column_encryptor,
    std::shared_ptr<SchemaManager> schema_manager,
    std::shared_ptr<TenantManager> tenant_manager,
    std::shared_ptr<AuditSampler> audit_sampler,
    std::shared_ptr<ResultCache> result_cache,
    std::shared_ptr<SlowQueryTracker> slow_query_tracker,
    std::shared_ptr<CircuitBreaker> circuit_breaker,
    std::shared_ptr<IConnectionPool> connection_pool,
    std::shared_ptr<ParseCache> parse_cache)
    : parser_(std::move(parser)),
      policy_engine_(std::move(policy_engine)),
      rate_limiter_(std::move(rate_limiter)),
      executor_(std::move(executor)),
      classifier_(std::move(classifier)),
      audit_emitter_(std::move(audit_emitter)),
      rewriter_(std::move(rewriter)),
      router_(std::move(router)),
      prepared_(std::move(prepared)),
      injection_detector_(std::move(injection_detector)),
      anomaly_detector_(std::move(anomaly_detector)),
      lineage_tracker_(std::move(lineage_tracker)),
      column_encryptor_(std::move(column_encryptor)),
      schema_manager_(std::move(schema_manager)),
      tenant_manager_(std::move(tenant_manager)),
      audit_sampler_(std::move(audit_sampler)),
      result_cache_(std::move(result_cache)),
      slow_query_tracker_(std::move(slow_query_tracker)),
      circuit_breaker_(std::move(circuit_breaker)),
      connection_pool_(std::move(connection_pool)),
      parse_cache_(std::move(parse_cache)) {}

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
    std::shared_ptr<PolicyEngine> active_policy_engine = policy_engine_;
    std::shared_ptr<IRateLimiter> active_rate_limiter = rate_limiter_;
    std::shared_ptr<AuditEmitter> active_audit_emitter = audit_emitter_;

    if (tenant_manager_ && !ctx.tenant_id.empty()) {
        const auto tenant_ctx = tenant_manager_->resolve(ctx.tenant_id);
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
    if (result_cache_ && result_cache_->is_enabled() &&
        ctx.analysis.statement_type == StatementType::SELECT &&
        ctx.fingerprint.has_value()) {
        const auto cached = result_cache_->get(
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

    // Dry-run mode: skip execution and everything after
    if (ctx.dry_run) {
        ctx.query_result.success = true;
        emit_audit(ctx);
        return build_response(ctx);
    }

    // Layer 5: Execute
    if (!execute_query(ctx)) {
        emit_audit(ctx);
        return build_response(ctx);
    }

    // Layer 5.01: Slow query tracking
    if (slow_query_tracker_ && slow_query_tracker_->is_enabled()) {
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
        slow_query_tracker_->record_if_slow(sq);
    }

    // Layer 5.02: Parse cache DDL invalidation
    if (parse_cache_ && ctx.query_result.success &&
        stmt_mask::test(ctx.analysis.statement_type, stmt_mask::kDDL) &&
        ctx.statement_info &&
        ctx.statement_info->parsed.ddl_object_name.has_value()) {
        parse_cache_->invalidate_table(*ctx.statement_info->parsed.ddl_object_name);
    }

    // Layer 5.05: Cache result (only for successful SELECTs)
    if (result_cache_ && result_cache_->is_enabled() &&
        ctx.query_result.success &&
        ctx.analysis.statement_type == StatementType::SELECT &&
        ctx.fingerprint.has_value()) {
        result_cache_->put(ctx.fingerprint->hash, ctx.user, ctx.database,
                           ctx.query_result);
    }

    // Write-invalidation (clear cache for modified database)
    if (result_cache_ && stmt_mask::test(ctx.analysis.statement_type, stmt_mask::kWrite | stmt_mask::kDDL)) {
        result_cache_->invalidate(ctx.database);
    }

    // Layer 5.1: Record DDL change (after successful execution)
    if (schema_manager_ && stmt_mask::test(ctx.analysis.statement_type, stmt_mask::kDDL)) {
        std::string table_name;
        if (!ctx.analysis.source_tables.empty()) {
            table_name = ctx.analysis.source_tables[0].table;
        }
        schema_manager_->record_change(ctx.user, ctx.database, table_name,
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
    const auto result = rate_limiter_->check(ctx.user, ctx.database);
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
    utils::Timer timer;

    // Resolve parser via router (per-database), fallback to default
    ISqlParser* active_parser = parser_.get();
    if (router_) {
        const auto routed = router_->get_parser(ctx.database);
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
    utils::Timer timer;

    ctx.policy_result = policy_engine_->evaluate(
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
    if (!rewriter_) return;

    std::string rewritten = rewriter_->rewrite(
        ctx.sql, ctx.user, ctx.roles, ctx.database,
        ctx.analysis, ctx.user_attributes);

    if (!rewritten.empty()) {
        ctx.original_sql = ctx.sql;
        ctx.sql = std::move(rewritten);
        ctx.sql_rewritten = true;
    }
}

bool Pipeline::execute_query(RequestContext& ctx) {
    // Resolve executor via router (per-database), fallback to default
    IQueryExecutor* exec = nullptr;
    if (router_) {
        const auto routed = router_->get_executor(ctx.database);
        if (routed) exec = routed.get();
    }
    if (!exec) exec = executor_.get();

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

    ctx.column_decisions = policy_engine_->evaluate_columns(
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
            new_columns.push_back(std::move(ctx.query_result.column_names[i]));
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
                new_row.push_back(std::move(row[i]));
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
            surviving.push_back(std::move(ctx.column_decisions[i]));
        }
    }
    ctx.column_decisions = std::move(surviving);
}

void Pipeline::apply_masking(RequestContext& ctx) {
    if (!ctx.query_result.success || ctx.column_decisions.empty()) return;

    utils::Timer timer;

    ctx.masking_applied = MaskingEngine::apply(ctx.query_result, ctx.column_decisions);

    ctx.masking_time = timer.elapsed_us();
}

void Pipeline::classify_results(RequestContext& ctx) {
    if (!classifier_ || !ctx.query_result.success) {
        return;
    }

    utils::Timer timer;

    ctx.classification_result = classifier_->classify(
        ctx.query_result,
        ctx.analysis
    );

    ctx.classification_time = timer.elapsed_us();
}

void Pipeline::emit_audit(const RequestContext& ctx) {
    if (!audit_emitter_) {
        return;
    }

    // Audit sampling check (before building the record)
    if (audit_sampler_ && audit_sampler_->is_enabled()) {
        const uint64_t fp = ctx.fingerprint.has_value() ? ctx.fingerprint->hash : 0;
        StatementType st = ctx.statement_info
            ? ctx.statement_info->parsed.type : StatementType::UNKNOWN;
        Decision decision = ctx.rate_limited ? Decision::BLOCK : ctx.policy_result.decision;
        if (!audit_sampler_->should_sample(st, decision, ctx.query_result.error_code, fp)) {
            return;
        }
    }

    AuditRecord record;
    record.trace_id = ctx.trace_context.trace_id;
    record.span_id = ctx.trace_context.span_id;
    record.parent_span_id = ctx.trace_context.parent_span_id;
    record.timestamp = ctx.received_at;
    record.user = ctx.user;
    record.source_ip = ctx.source_ip;
    record.database_name = ctx.database;
    record.sql = ctx.sql;

    if (ctx.fingerprint.has_value()) {
        record.fingerprint.hash = ctx.fingerprint->hash;
        record.fingerprint.normalized = ctx.fingerprint->normalized;
    }

    if (ctx.statement_info) {
        record.statement_type = ctx.statement_info->parsed.type;
    }

    record.decision = ctx.rate_limited ? Decision::BLOCK : ctx.policy_result.decision;
    record.matched_policy = ctx.policy_result.matched_policy;
    record.block_reason = ctx.policy_result.reason;

    // Shadow mode
    record.shadow_blocked = ctx.policy_result.shadow_blocked;
    record.shadow_policy = ctx.policy_result.shadow_policy;

    record.execution_success = ctx.query_result.success;
    record.error_code = ctx.query_result.error_code;
    record.error_message = ctx.query_result.error_message;
    record.rows_returned = ctx.query_result.rows.size();

    record.detected_classifications = ctx.classification_result.get_classified_types();

    record.parse_time = ctx.parse_time;
    record.policy_time = ctx.policy_time;
    record.execution_time = ctx.execution_time;
    record.classification_time = ctx.classification_time;

    const auto elapsed = std::chrono::steady_clock::now() - ctx.started_at;
    record.total_duration = std::chrono::duration_cast<std::chrono::microseconds>(elapsed);

    record.rate_limited = ctx.rate_limited;
    record.cache_hit = ctx.cache_hit;

    // Masking / query rewriting audit fields
    for (const auto& m : ctx.masking_applied) {
        record.masked_columns.push_back(m.column_name);
    }
    record.sql_rewritten = ctx.sql_rewritten;
    if (ctx.sql_rewritten) {
        record.original_sql = ctx.original_sql;
    }

    // Security fields
    record.threat_level = SqlInjectionDetector::threat_level_to_string(
        ctx.injection_result.threat_level);
    record.injection_patterns = ctx.injection_result.patterns_matched;
    record.injection_blocked = ctx.injection_result.should_block;
    record.anomaly_score = ctx.anomaly_result.anomaly_score;
    record.anomalies = ctx.anomaly_result.anomalies;

    audit_emitter_->emit(std::move(record));
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
    if (!injection_detector_) return true;

    utils::Timer timer;

    std::string normalized;
    if (ctx.fingerprint.has_value()) {
        normalized = ctx.fingerprint->normalized;
    }

    ctx.injection_result = injection_detector_->analyze(
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
    if (!anomaly_detector_) return;

    // Collect table names from analysis
    std::vector<std::string> tables;
    tables.reserve(ctx.analysis.source_tables.size());
    for (const auto& t : ctx.analysis.source_tables) {
        tables.push_back(t.table);
    }

    const uint64_t fp_hash = ctx.fingerprint.has_value() ? ctx.fingerprint->hash : 0;

    // Check for anomalies (read-only scoring)
    ctx.anomaly_result = anomaly_detector_->check(ctx.user, tables, fp_hash);

    // Record this query in the user's profile (updates state)
    anomaly_detector_->record(ctx.user, tables, fp_hash);
}

void Pipeline::decrypt_columns(RequestContext& ctx) {
    if (!column_encryptor_ || !column_encryptor_->is_enabled()) return;
    if (!ctx.query_result.success || ctx.query_result.rows.empty()) return;

    column_encryptor_->decrypt_result(ctx.query_result, ctx.database, ctx.analysis);
}

void Pipeline::record_lineage(RequestContext& ctx) {
    if (!lineage_tracker_) return;
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

        lineage_tracker_->record(event);
    }
}

bool Pipeline::intercept_ddl(RequestContext& ctx) {
    if (!schema_manager_) return true;
    if (!ctx.statement_info) return true;

    // Only intercept DDL statements
    if (!stmt_mask::test(ctx.analysis.statement_type, stmt_mask::kDDL)) return true;

    const bool allowed = schema_manager_->intercept_ddl(
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

// Stubs for prepared statement handling
void Pipeline::handle_prepare(RequestContext& /*ctx*/) {}
void Pipeline::handle_execute(RequestContext& /*ctx*/) {}
void Pipeline::handle_deallocate(RequestContext& /*ctx*/) {}

} // namespace sqlproxy
