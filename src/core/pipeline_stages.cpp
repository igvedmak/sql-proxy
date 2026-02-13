#include "core/pipeline_stages.hpp"
#include "core/query_rewriter.hpp"
#include "core/query_cost_estimator.hpp"
#include "core/cost_based_rewriter.hpp"
#include "db/database_router.hpp"
#include "db/isql_parser.hpp"
#include "policy/policy_engine.hpp"
#include "server/irate_limiter.hpp"
#include "security/sql_injection_detector.hpp"
#include "security/anomaly_detector.hpp"
#include "security/sql_firewall.hpp"
#include "tenant/data_residency.hpp"
#include "schema/schema_manager.hpp"
#include "cache/result_cache.hpp"
#include "classifier/classifier_registry.hpp"
#include "tracing/span.hpp"

namespace sqlproxy {

// ============================================================================
// DataResidencyStage
// ============================================================================
IPipelineStage::Result DataResidencyStage::process(RequestContext& ctx) {
    if (!c_.data_residency_enforcer || !c_.data_residency_enforcer->is_enabled()) return Result::CONTINUE;
    if (ctx.tenant_id.empty()) return Result::CONTINUE;

    const auto result = c_.data_residency_enforcer->check(ctx.tenant_id, ctx.database);
    if (!result.allowed) {
        ctx.query_result.success = false;
        ctx.query_result.error_code = ErrorCode::RESIDENCY_BLOCKED;
        ctx.query_result.error_message = result.reason;
        return Result::BLOCK;
    }
    return Result::CONTINUE;
}

// ============================================================================
// RateLimitStage
// ============================================================================
IPipelineStage::Result RateLimitStage::process(RequestContext& ctx) {
    ScopedSpan span(ctx, "sql_proxy.rate_limit");
    const auto result = c_.rate_limiter->check(ctx.user, ctx.database);
    ctx.rate_limit_result = result;
    if (!result.allowed) {
        ctx.rate_limited = true;
        ctx.query_result.success = false;
        ctx.query_result.error_code = ErrorCode::RATE_LIMITED;

        std::string msg;
        msg.reserve(16 + result.level.size() + 6);
        msg = "Rate limited at ";
        msg += result.level;
        msg += " level";
        ctx.query_result.error_message = std::move(msg);

        return Result::BLOCK;
    }
    return Result::CONTINUE;
}

// ============================================================================
// ParseStage
// ============================================================================
IPipelineStage::Result ParseStage::process(RequestContext& ctx) {
    ScopedSpan span(ctx, "sql_proxy.parse");
    utils::Timer timer;

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
        return Result::BLOCK;
    }

    ctx.statement_info = parse_result.statement_info;
    ctx.fingerprint = ctx.statement_info->fingerprint;
    return Result::CONTINUE;
}

// ============================================================================
// AnalyzeStage
// ============================================================================
IPipelineStage::Result AnalyzeStage::process(RequestContext& ctx) {
    if (!ctx.statement_info) return Result::BLOCK;

    ctx.analysis = SQLAnalyzer::analyze(ctx.statement_info->parsed, nullptr);
    return Result::CONTINUE;
}

// ============================================================================
// ResultCacheLookupStage
// ============================================================================
IPipelineStage::Result ResultCacheLookupStage::process(RequestContext& ctx) {
    if (!c_.result_cache || !c_.result_cache->is_enabled()) return Result::CONTINUE;
    if (ctx.analysis.statement_type != StatementType::SELECT) return Result::CONTINUE;
    if (!ctx.fingerprint.has_value()) return Result::CONTINUE;

    const auto cached = c_.result_cache->get(ctx.fingerprint->hash, ctx.user, ctx.database);
    if (cached) {
        ctx.query_result = std::move(*cached);
        ctx.cache_hit = true;
        // Classification + lineage + audit handled by Pipeline after SHORT_CIRCUIT
        return Result::SHORT_CIRCUIT;
    }
    return Result::CONTINUE;
}

// ============================================================================
// InjectionDetectionStage
// ============================================================================
IPipelineStage::Result InjectionDetectionStage::process(RequestContext& ctx) {
    if (!c_.injection_detector) return Result::CONTINUE;

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
        return Result::BLOCK;
    }
    return Result::CONTINUE;
}

// ============================================================================
// AnomalyDetectionStage
// ============================================================================
IPipelineStage::Result AnomalyDetectionStage::process(RequestContext& ctx) {
    if (!c_.anomaly_detector) return Result::CONTINUE;

    std::vector<std::string> tables;
    tables.reserve(ctx.analysis.source_tables.size());
    for (const auto& t : ctx.analysis.source_tables) {
        tables.push_back(t.table);
    }

    const uint64_t fp_hash = ctx.fingerprint.has_value() ? ctx.fingerprint->hash : 0;

    ctx.anomaly_result = c_.anomaly_detector->check(ctx.user, tables, fp_hash);
    c_.anomaly_detector->record(ctx.user, tables, fp_hash);

    return Result::CONTINUE;  // Informational only — never blocks
}

// ============================================================================
// FirewallStage
// ============================================================================
IPipelineStage::Result FirewallStage::process(RequestContext& ctx) {
    if (!c_.sql_firewall || !c_.sql_firewall->is_enabled()) return Result::CONTINUE;
    if (!ctx.fingerprint.has_value()) return Result::CONTINUE;

    const uint64_t fp = ctx.fingerprint->hash;
    const auto result = c_.sql_firewall->check(fp);

    if (c_.sql_firewall->mode() == FirewallMode::LEARNING) {
        c_.sql_firewall->record(fp);
    }

    if (!result.allowed) {
        ctx.query_result.success = false;
        ctx.query_result.error_code = ErrorCode::FIREWALL_BLOCKED;
        ctx.query_result.error_message = "Query blocked by SQL firewall: unknown fingerprint";
        return Result::BLOCK;
    }
    return Result::CONTINUE;
}

// ============================================================================
// PolicyStage
// ============================================================================
IPipelineStage::Result PolicyStage::process(RequestContext& ctx) {
    ScopedSpan span(ctx, "sql_proxy.policy");
    utils::Timer timer;

    ctx.policy_result = c_.policy_engine->evaluate(
        ctx.user, ctx.roles, ctx.database, ctx.analysis);

    ctx.policy_time = timer.elapsed_us();

    if (ctx.policy_result.decision != Decision::ALLOW) {
        ctx.query_result.success = false;
        ctx.query_result.error_code = ErrorCode::ACCESS_DENIED;
        ctx.query_result.error_message = ctx.policy_result.reason;
        return Result::BLOCK;
    }
    return Result::CONTINUE;
}

// ============================================================================
// DdlInterceptStage
// ============================================================================
IPipelineStage::Result DdlInterceptStage::process(RequestContext& ctx) {
    if (!c_.schema_manager) return Result::CONTINUE;
    if (!ctx.statement_info) return Result::CONTINUE;
    if (!stmt_mask::test(ctx.analysis.statement_type, stmt_mask::kDDL)) return Result::CONTINUE;

    const bool allowed = c_.schema_manager->intercept_ddl(
        ctx.user, ctx.database, ctx.sql, ctx.analysis.statement_type);

    if (!allowed) {
        ctx.ddl_requires_approval = true;
        ctx.query_result.success = false;
        ctx.query_result.error_code = ErrorCode::ACCESS_DENIED;
        ctx.query_result.error_message = "DDL requires approval — submitted for review";
        return Result::BLOCK;
    }
    return Result::CONTINUE;
}

// ============================================================================
// RewriteStage
// ============================================================================
IPipelineStage::Result RewriteStage::process(RequestContext& ctx) {
    if (!c_.rewriter) return Result::CONTINUE;

    const uint64_t fp = ctx.fingerprint.has_value() ? ctx.fingerprint->hash : 0;
    std::string rewritten = c_.rewriter->rewrite(
        ctx.sql, ctx.user, ctx.roles, ctx.database,
        ctx.analysis, ctx.user_attributes, fp);

    if (!rewritten.empty()) {
        ctx.original_sql = ctx.sql;
        ctx.sql = std::move(rewritten);
        ctx.sql_rewritten = true;
    }
    return Result::CONTINUE;
}

// ============================================================================
// CostRewriteStage
// ============================================================================
IPipelineStage::Result CostRewriteStage::process(RequestContext& ctx) {
    if (!c_.cost_based_rewriter || !c_.cost_based_rewriter->is_enabled()) return Result::CONTINUE;

    const auto result = c_.cost_based_rewriter->rewrite_if_expensive(ctx.sql, ctx.analysis);
    if (result.rewritten) {
        if (!ctx.sql_rewritten) {
            ctx.original_sql = ctx.sql;
        }
        ctx.sql = result.new_sql;
        ctx.sql_rewritten = true;
    }
    return Result::CONTINUE;
}

// ============================================================================
// CostCheckStage
// ============================================================================
IPipelineStage::Result CostCheckStage::process(RequestContext& ctx) {
    if (!c_.query_cost_estimator || !c_.query_cost_estimator->is_enabled()) return Result::CONTINUE;
    if (ctx.analysis.statement_type != StatementType::SELECT) return Result::CONTINUE;

    const uint64_t fp = ctx.fingerprint.has_value() ? ctx.fingerprint->hash : 0;
    const auto estimate = c_.query_cost_estimator->estimate(ctx.sql, fp);
    if (estimate.is_rejected()) {
        ctx.query_result.success = false;
        ctx.query_result.error_code = ErrorCode::QUERY_TOO_EXPENSIVE;
        ctx.query_result.error_message = std::format(
            "Query too expensive: cost={:.1f} rows={} plan={}",
            estimate.total_cost, estimate.estimated_rows, estimate.plan_type);
        return Result::BLOCK;
    }
    return Result::CONTINUE;
}

} // namespace sqlproxy
