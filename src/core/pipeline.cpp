#include "core/pipeline.hpp"
#include "core/masking.hpp"
#include "core/query_rewriter.hpp"
#include "core/utils.hpp"
#include "classifier/classifier_registry.hpp"
#include "audit/audit_emitter.hpp"
#include "db/database_router.hpp"

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
    std::shared_ptr<PreparedStatementTracker> prepared)
    : parser_(std::move(parser)),
      policy_engine_(std::move(policy_engine)),
      rate_limiter_(std::move(rate_limiter)),
      executor_(std::move(executor)),
      classifier_(std::move(classifier)),
      audit_emitter_(std::move(audit_emitter)),
      rewriter_(std::move(rewriter)),
      router_(std::move(router)),
      prepared_(std::move(prepared)) {}

ProxyResponse Pipeline::execute(const ProxyRequest& request) {
    RequestContext ctx;
    ctx.request_id = request.request_id;
    ctx.user = request.user;
    ctx.roles = request.roles;
    ctx.database = request.database;
    ctx.sql = request.sql;
    ctx.source_ip = request.source_ip;
    ctx.user_attributes = request.user_attributes;

    // Layer 1: Rate limiting
    if (!check_rate_limit(ctx)) {
        emit_audit(ctx);
        return build_response(ctx);
    }

    // Layer 2: Parse + Cache
    if (!parse_query(ctx)) {
        emit_audit(ctx);
        return build_response(ctx);
    }

    // Layer 3: Analyze
    if (!analyze_query(ctx)) {
        emit_audit(ctx);
        return build_response(ctx);
    }

    // Layer 4: Policy evaluation (table-level)
    if (!evaluate_policy(ctx)) {
        emit_audit(ctx);
        return build_response(ctx);
    }

    // Layer 4.5: Query rewriting (RLS + enforce_limit)
    rewrite_query(ctx);

    // Layer 5: Execute
    if (!execute_query(ctx)) {
        emit_audit(ctx);
        return build_response(ctx);
    }

    // Layer 5.5: Column-level ACL (remove blocked columns)
    apply_column_policies(ctx);

    // Layer 5.6: Data masking (mask values in-place)
    apply_masking(ctx);

    // Layer 6: Classify (runs on masked data — won't double-report PII)
    classify_results(ctx);

    // Build response first (response should not wait on audit I/O)
    auto response = build_response(ctx);

    // Layer 7: Audit (after response is ready — emit is non-blocking ring buffer push)
    emit_audit(ctx);

    return response;
}

bool Pipeline::check_rate_limit(RequestContext& ctx) {
    auto result = rate_limiter_->check(ctx.user, ctx.database);
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
        auto routed = router_->get_parser(ctx.database);
        if (routed) active_parser = routed.get();
    }

    auto parse_result = active_parser->parse(ctx.sql);
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
        auto routed = router_->get_executor(ctx.database);
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

    AuditRecord record;
    record.audit_id = utils::generate_uuid();
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

    record.execution_success = ctx.query_result.success;
    record.error_code = ctx.query_result.error_code;
    record.error_message = ctx.query_result.error_message;
    record.rows_returned = ctx.query_result.rows.size();

    record.detected_classifications = ctx.classification_result.get_classified_types();

    record.parse_time = ctx.parse_time;
    record.policy_time = ctx.policy_time;
    record.execution_time = ctx.execution_time;
    record.classification_time = ctx.classification_time;

    auto elapsed = std::chrono::steady_clock::now() - ctx.started_at;
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

    audit_emitter_->emit(std::move(record));
}

ProxyResponse Pipeline::build_response(const RequestContext& ctx) {
    ProxyResponse response;
    response.request_id = ctx.request_id;
    response.audit_id = utils::generate_uuid();
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

    auto elapsed = std::chrono::steady_clock::now() - ctx.started_at;
    response.execution_time_ms = std::chrono::duration_cast<std::chrono::microseconds>(elapsed);

    response.policy_decision = ctx.policy_result.decision;
    response.matched_policy = ctx.policy_result.matched_policy;

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

// Stubs for prepared statement handling — implemented in Phase 5
void Pipeline::handle_prepare(RequestContext& /*ctx*/) {}
void Pipeline::handle_execute(RequestContext& /*ctx*/) {}
void Pipeline::handle_deallocate(RequestContext& /*ctx*/) {}

} // namespace sqlproxy
