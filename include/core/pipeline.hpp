#pragma once

#include "audit/audit_emitter.hpp"
#include "core/types.hpp"
#include "core/request_context.hpp"
#include "core/pipeline_builder.hpp"
#include "db/isql_parser.hpp"
#include "db/iquery_executor.hpp"
#include "policy/policy_engine.hpp"
#include "server/irate_limiter.hpp"
#include <atomic>
#include <memory>

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
    bool check_rate_limit(RequestContext& ctx);
    bool parse_query(RequestContext& ctx);
    bool analyze_query(RequestContext& ctx);
    bool evaluate_policy(RequestContext& ctx);
    bool execute_query(RequestContext& ctx);
    void classify_results(RequestContext& ctx);
    void emit_audit(const RequestContext& ctx);
    void rewrite_query(RequestContext& ctx);
    void apply_column_policies(RequestContext& ctx);
    void apply_masking(RequestContext& ctx);
    ProxyResponse build_response(const RequestContext& ctx);
    bool check_injection(RequestContext& ctx);
    void check_anomaly(RequestContext& ctx);
    void decrypt_columns(RequestContext& ctx);
    void record_lineage(RequestContext& ctx);
    bool intercept_ddl(RequestContext& ctx);
    bool check_query_cost(RequestContext& ctx);

    PipelineComponents c_;
    RetryConfig retry_config_;

    mutable std::atomic<uint64_t> total_requests_{0};
    mutable std::atomic<uint64_t> requests_blocked_{0};
};

} // namespace sqlproxy
