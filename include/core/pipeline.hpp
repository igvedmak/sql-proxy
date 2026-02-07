#pragma once

#include "audit/audit_emitter.hpp"
#include "core/types.hpp"
#include "core/request_context.hpp"
#include "parser/sql_parser.hpp"
#include "policy/policy_engine.hpp"
#include "server/rate_limiter.hpp"
#include <memory>

namespace sqlproxy {

// Forward declarations
class QueryExecutor;
class ClassifierRegistry;

/**
 * @brief Pipeline coordinator - orchestrates 7-layer request flow
 *
 * Layers:
 * 1. Ingress (rate limit, validate)
 * 2. Parse + Cache
 * 3. Analyze
 * 4. Policy
 * 5. Execute
 * 6. Classify
 * 7. Audit
 */
class Pipeline {
public:
    /**
     * @brief Construct pipeline with components
     */
    Pipeline(
        std::shared_ptr<SQLParser> parser,
        std::shared_ptr<PolicyEngine> policy_engine,
        std::shared_ptr<HierarchicalRateLimiter> rate_limiter,
        std::shared_ptr<QueryExecutor> executor,
        std::shared_ptr<ClassifierRegistry> classifier,
        std::shared_ptr<AuditEmitter> audit_emitter
    );

    /**
     * @brief Execute request through pipeline
     * @param request Incoming request
     * @return Response with result or error
     */
    ProxyResponse execute(const ProxyRequest& request);

    /**
     * @brief Get policy engine (for hot reload)
     */
    std::shared_ptr<PolicyEngine> get_policy_engine() const { return policy_engine_; }

    /**
     * @brief Get rate limiter (for metrics)
     */
    std::shared_ptr<HierarchicalRateLimiter> get_rate_limiter() const { return rate_limiter_; }

    /**
     * @brief Get audit emitter (for metrics)
     */
    std::shared_ptr<AuditEmitter> get_audit_emitter() const { return audit_emitter_; }

private:
    /**
     * @brief Layer 1: Ingress - rate limit and validate
     */
    bool check_rate_limit(RequestContext& ctx);

    /**
     * @brief Layer 2: Parse + Cache
     */
    bool parse_query(RequestContext& ctx);

    /**
     * @brief Layer 3: Analyze
     */
    bool analyze_query(RequestContext& ctx);

    /**
     * @brief Layer 4: Policy evaluation
     */
    bool evaluate_policy(RequestContext& ctx);

    /**
     * @brief Layer 5: Execute query
     */
    bool execute_query(RequestContext& ctx);

    /**
     * @brief Layer 6: Classify results
     */
    void classify_results(RequestContext& ctx);

    /**
     * @brief Layer 7: Emit audit record
     */
    void emit_audit(const RequestContext& ctx);

    /**
     * @brief Build response from context
     */
    ProxyResponse build_response(const RequestContext& ctx);

    const std::shared_ptr<SQLParser> parser_;
    const std::shared_ptr<PolicyEngine> policy_engine_;
    const std::shared_ptr<HierarchicalRateLimiter> rate_limiter_;
    const std::shared_ptr<QueryExecutor> executor_;
    const std::shared_ptr<ClassifierRegistry> classifier_;
    const std::shared_ptr<AuditEmitter> audit_emitter_;
};

} // namespace sqlproxy
