#pragma once

#include <memory>

namespace sqlproxy {

// Forward declarations
class ISqlParser;
class PolicyEngine;
class IRateLimiter;
class IQueryExecutor;
class ClassifierRegistry;
class AuditEmitter;
class QueryRewriter;
class DatabaseRouter;
class PreparedStatementTracker;
class SqlInjectionDetector;
class AnomalyDetector;
class LineageTracker;
class ColumnEncryptor;
class SchemaManager;
class TenantManager;
class AuditSampler;
class ResultCache;
class SlowQueryTracker;
class CircuitBreaker;
class CircuitBreakerRegistry;
class IConnectionPool;
class ParseCache;
class QueryCostEstimator;
class AdaptiveRateController;
class Pipeline;

/**
 * @brief All components that Pipeline needs, grouped in a single struct.
 *
 * Replaces the 23-parameter constructor: adding a new component only
 * requires adding a field here (no signature changes anywhere).
 */
struct PipelineComponents {
    // Required (core pipeline)
    std::shared_ptr<ISqlParser> parser;
    std::shared_ptr<PolicyEngine> policy_engine;
    std::shared_ptr<IRateLimiter> rate_limiter;
    std::shared_ptr<IQueryExecutor> executor;
    std::shared_ptr<ClassifierRegistry> classifier;
    std::shared_ptr<AuditEmitter> audit_emitter;

    // Optional (nullptr = disabled)
    std::shared_ptr<QueryRewriter> rewriter;
    std::shared_ptr<DatabaseRouter> router;
    std::shared_ptr<PreparedStatementTracker> prepared;
    std::shared_ptr<SqlInjectionDetector> injection_detector;
    std::shared_ptr<AnomalyDetector> anomaly_detector;
    std::shared_ptr<LineageTracker> lineage_tracker;
    std::shared_ptr<ColumnEncryptor> column_encryptor;
    std::shared_ptr<SchemaManager> schema_manager;
    std::shared_ptr<TenantManager> tenant_manager;
    std::shared_ptr<AuditSampler> audit_sampler;
    std::shared_ptr<ResultCache> result_cache;
    std::shared_ptr<SlowQueryTracker> slow_query_tracker;
    std::shared_ptr<CircuitBreaker> circuit_breaker;
    std::shared_ptr<CircuitBreakerRegistry> circuit_breaker_registry;
    std::shared_ptr<IConnectionPool> connection_pool;
    std::shared_ptr<ParseCache> parse_cache;
    std::shared_ptr<QueryCostEstimator> query_cost_estimator;
    std::shared_ptr<AdaptiveRateController> adaptive_rate_controller;

    // Feature flags (non-component toggles)
    bool masking_enabled = true;
};

/**
 * @brief Builder pattern for Pipeline construction.
 *
 * Usage:
 *   auto pipeline = PipelineBuilder()
 *       .with_parser(parser)
 *       .with_policy_engine(engine)
 *       .with_rate_limiter(limiter)
 *       .with_executor(executor)
 *       .with_classifier(classifier)
 *       .with_audit_emitter(emitter)
 *       .with_injection_detector(detector)  // optional
 *       .build();
 */
class PipelineBuilder {
public:
    PipelineBuilder& with_parser(std::shared_ptr<ISqlParser> p)              { c_.parser = std::move(p); return *this; }
    PipelineBuilder& with_policy_engine(std::shared_ptr<PolicyEngine> p)     { c_.policy_engine = std::move(p); return *this; }
    PipelineBuilder& with_rate_limiter(std::shared_ptr<IRateLimiter> p)      { c_.rate_limiter = std::move(p); return *this; }
    PipelineBuilder& with_executor(std::shared_ptr<IQueryExecutor> p)        { c_.executor = std::move(p); return *this; }
    PipelineBuilder& with_classifier(std::shared_ptr<ClassifierRegistry> p)  { c_.classifier = std::move(p); return *this; }
    PipelineBuilder& with_audit_emitter(std::shared_ptr<AuditEmitter> p)     { c_.audit_emitter = std::move(p); return *this; }
    PipelineBuilder& with_rewriter(std::shared_ptr<QueryRewriter> p)         { c_.rewriter = std::move(p); return *this; }
    PipelineBuilder& with_router(std::shared_ptr<DatabaseRouter> p)          { c_.router = std::move(p); return *this; }
    PipelineBuilder& with_prepared(std::shared_ptr<PreparedStatementTracker> p) { c_.prepared = std::move(p); return *this; }
    PipelineBuilder& with_injection_detector(std::shared_ptr<SqlInjectionDetector> p)  { c_.injection_detector = std::move(p); return *this; }
    PipelineBuilder& with_anomaly_detector(std::shared_ptr<AnomalyDetector> p)         { c_.anomaly_detector = std::move(p); return *this; }
    PipelineBuilder& with_lineage_tracker(std::shared_ptr<LineageTracker> p)            { c_.lineage_tracker = std::move(p); return *this; }
    PipelineBuilder& with_column_encryptor(std::shared_ptr<ColumnEncryptor> p)          { c_.column_encryptor = std::move(p); return *this; }
    PipelineBuilder& with_schema_manager(std::shared_ptr<SchemaManager> p)              { c_.schema_manager = std::move(p); return *this; }
    PipelineBuilder& with_tenant_manager(std::shared_ptr<TenantManager> p)              { c_.tenant_manager = std::move(p); return *this; }
    PipelineBuilder& with_audit_sampler(std::shared_ptr<AuditSampler> p)                { c_.audit_sampler = std::move(p); return *this; }
    PipelineBuilder& with_result_cache(std::shared_ptr<ResultCache> p)                  { c_.result_cache = std::move(p); return *this; }
    PipelineBuilder& with_slow_query_tracker(std::shared_ptr<SlowQueryTracker> p)       { c_.slow_query_tracker = std::move(p); return *this; }
    PipelineBuilder& with_circuit_breaker(std::shared_ptr<CircuitBreaker> p)            { c_.circuit_breaker = std::move(p); return *this; }
    PipelineBuilder& with_circuit_breaker_registry(std::shared_ptr<CircuitBreakerRegistry> p) { c_.circuit_breaker_registry = std::move(p); return *this; }
    PipelineBuilder& with_connection_pool(std::shared_ptr<IConnectionPool> p)           { c_.connection_pool = std::move(p); return *this; }
    PipelineBuilder& with_parse_cache(std::shared_ptr<ParseCache> p)                    { c_.parse_cache = std::move(p); return *this; }
    PipelineBuilder& with_query_cost_estimator(std::shared_ptr<QueryCostEstimator> p)   { c_.query_cost_estimator = std::move(p); return *this; }
    PipelineBuilder& with_adaptive_rate_controller(std::shared_ptr<AdaptiveRateController> p) { c_.adaptive_rate_controller = std::move(p); return *this; }
    PipelineBuilder& with_masking_enabled(bool enabled)                                       { c_.masking_enabled = enabled; return *this; }

    /**
     * @brief Build the Pipeline from accumulated components.
     * @throws std::runtime_error if required components are missing.
     */
    [[nodiscard]] std::shared_ptr<Pipeline> build();

private:
    PipelineComponents c_;
};

} // namespace sqlproxy
