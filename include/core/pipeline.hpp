#pragma once

#include "audit/audit_emitter.hpp"
#include "core/types.hpp"
#include "core/request_context.hpp"
#include "core/pipeline_builder.hpp"
#include "core/pipeline_stage.hpp"
#include "db/isql_parser.hpp"
#include "db/iquery_executor.hpp"
#include "policy/policy_engine.hpp"
#include "server/irate_limiter.hpp"
#include <atomic>
#include <memory>
#include <vector>

namespace sqlproxy {

/**
 * @brief Pipeline coordinator - orchestrates 7-layer request flow
 *
 * Layers:
 * 1. Ingress (rate limit, validate)
 * 2. Parse + Cache
 * 3. Analyze
 * 4. Policy (table-level)
 * 4.5. Rewrite query (RLS + enforce_limit)
 * 5. Execute
 * 5.5. Column-level ACL (remove blocked columns)
 * 5.6. Data masking (mask values in-place)
 * 6. Classify (on masked data)
 * 7. Audit
 */
class Pipeline {
public:
    /**
     * @brief Construct pipeline from components struct (preferred)
     */
    explicit Pipeline(PipelineComponents components);

    struct RetryConfig {
        bool enabled = false;
        int max_retries = 1;
        int initial_backoff_ms = 100;
        int max_backoff_ms = 2000;
    };

    void set_retry_config(RetryConfig config) { retry_config_ = config; }

    /**
     * @brief Execute request through pipeline
     * @param request Incoming request
     * @return Response with result or error
     */
    ProxyResponse execute(const ProxyRequest& request);

    std::shared_ptr<PolicyEngine> get_policy_engine() const { return c_.policy_engine; }
    std::shared_ptr<IRateLimiter> get_rate_limiter() const { return c_.rate_limiter; }
    std::shared_ptr<AuditEmitter> get_audit_emitter() const { return c_.audit_emitter; }
    std::shared_ptr<ResultCache> get_result_cache() const { return c_.result_cache; }
    std::shared_ptr<SlowQueryTracker> get_slow_query_tracker() const { return c_.slow_query_tracker; }
    std::shared_ptr<CircuitBreaker> get_circuit_breaker() const { return c_.circuit_breaker; }
    std::shared_ptr<CircuitBreakerRegistry> get_circuit_breaker_registry() const { return c_.circuit_breaker_registry; }
    std::shared_ptr<IConnectionPool> get_connection_pool() const { return c_.connection_pool; }
    std::shared_ptr<ParseCache> get_parse_cache() const { return c_.parse_cache; }
    std::shared_ptr<QueryCostEstimator> get_query_cost_estimator() const { return c_.query_cost_estimator; }
    std::shared_ptr<AdaptiveRateController> get_adaptive_rate_controller() const { return c_.adaptive_rate_controller; }
    std::shared_ptr<ISqlParser> get_parser() const { return c_.parser; }
    std::shared_ptr<IndexRecommender> get_index_recommender() const { return c_.index_recommender; }
    std::shared_ptr<DataResidencyEnforcer> get_data_residency_enforcer() const { return c_.data_residency_enforcer; }
    std::shared_ptr<ColumnVersionTracker> get_column_version_tracker() const { return c_.column_version_tracker; }
    std::shared_ptr<CostBasedRewriter> get_cost_based_rewriter() const { return c_.cost_based_rewriter; }
    std::shared_ptr<TransactionCoordinator> get_transaction_coordinator() const { return c_.transaction_coordinator; }
    std::shared_ptr<LlmClient> get_llm_client() const { return c_.llm_client; }

    struct Stats {
        uint64_t total_requests;
        uint64_t requests_blocked;
    };

    [[nodiscard]] Stats get_stats() const {
        return {
            .total_requests = total_requests_.load(std::memory_order_relaxed),
            .requests_blocked = requests_blocked_.load(std::memory_order_relaxed),
        };
    }

private:
    // Pre-execute stages are handled by the stage chain (pre_execute_stages_)
    // Post-execute methods remain as private helpers
    [[nodiscard]] bool execute_query(RequestContext& ctx);
    void classify_results(RequestContext& ctx);
    void emit_audit(const RequestContext& ctx);
    void apply_column_policies(RequestContext& ctx);
    void apply_masking(RequestContext& ctx);
    [[nodiscard]] ProxyResponse build_response(const RequestContext& ctx);
    void decrypt_columns(RequestContext& ctx);
    void record_lineage(RequestContext& ctx);
    void record_column_versions(RequestContext& ctx);

    /**
     * @brief Build pre-execute stage chain from components
     */
    void build_stage_chain();

    PipelineComponents c_;

    /**
     * @brief Ordered chain of pre-execute stages
     *
     * Each stage returns CONTINUE, BLOCK, or SHORT_CIRCUIT.
     * Stages are built once in constructor and executed in order.
     */
    std::vector<std::unique_ptr<IPipelineStage>> pre_execute_stages_;
    RetryConfig retry_config_;

    mutable std::atomic<uint64_t> total_requests_{0};
    mutable std::atomic<uint64_t> requests_blocked_{0};
};

} // namespace sqlproxy
