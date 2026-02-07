#include "core/pipeline.hpp"
#include "core/utils.hpp"
#include "classifier/classifier_registry.hpp"
#include "audit/audit_emitter.hpp"

namespace sqlproxy {

Pipeline::Pipeline(
    std::shared_ptr<ISqlParser> parser,
    std::shared_ptr<PolicyEngine> policy_engine,
    std::shared_ptr<HierarchicalRateLimiter> rate_limiter,
    std::shared_ptr<IQueryExecutor> executor,
    std::shared_ptr<ClassifierRegistry> classifier,
    std::shared_ptr<AuditEmitter> audit_emitter)
    : parser_(std::move(parser)),
      policy_engine_(std::move(policy_engine)),
      rate_limiter_(std::move(rate_limiter)),
      executor_(std::move(executor)),
      classifier_(std::move(classifier)),
      audit_emitter_(std::move(audit_emitter)) {}

ProxyResponse Pipeline::execute(const ProxyRequest& request) {
    RequestContext ctx;
    ctx.request_id = request.request_id;
    ctx.user = request.user;
    ctx.roles = request.roles;  // Pass roles from request
    ctx.database = request.database;
    ctx.sql = request.sql;
    ctx.source_ip = request.source_ip;

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

    // Layer 4: Policy evaluation
    if (!evaluate_policy(ctx)) {
        emit_audit(ctx);
        return build_response(ctx);
    }

    // Layer 5: Execute
    if (!execute_query(ctx)) {
        emit_audit(ctx);
        return build_response(ctx);
    }

    // Layer 6: Classify
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

    auto parse_result = parser_->parse(ctx.sql);
    ctx.parse_time = timer.elapsed_us();

    if (!parse_result.success) {
        ctx.query_result.success = false;
        ctx.query_result.error_code = ErrorCode::PARSE_ERROR;
        ctx.query_result.error_message = parse_result.error_message;
        return false;
    }

    ctx.statement_info = parse_result.statement_info;
    ctx.fingerprint = ctx.statement_info->fingerprint;
    // Cache hit tracking would be in parser
    return true;
}

bool Pipeline::analyze_query(RequestContext& ctx) {
    if (!ctx.statement_info) {
        return false;
    }

    // Analysis is embedded in statement_info from parse cache
    // Or analyze fresh if cache miss
    ctx.analysis = SQLAnalyzer::analyze(
        ctx.statement_info->parsed,
        nullptr  // parse_tree not needed for basic analysis
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

bool Pipeline::execute_query(RequestContext& ctx) {
    if (!executor_) {
        // No executor configured - return mock success
        ctx.query_result.success = true;
        ctx.query_result.column_names = {"result"};
        ctx.query_result.rows = {{"mock_data"}};
        return true;
    }

    utils::Timer timer;

    ctx.query_result = executor_->execute(ctx.sql, ctx.analysis.statement_type);
    ctx.execution_time = timer.elapsed_us();

    return ctx.query_result.success;
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

    audit_emitter_->emit(std::move(record));
}

ProxyResponse Pipeline::build_response(const RequestContext& ctx) {
    ProxyResponse response;
    response.request_id = ctx.request_id;
    response.audit_id = utils::generate_uuid();  // Would come from audit record
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

    return response;
}

} // namespace sqlproxy
