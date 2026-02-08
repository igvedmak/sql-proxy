#pragma once

#include "audit/audit_emitter.hpp"
#include "core/types.hpp"
#include "core/request_context.hpp"
#include "db/isql_parser.hpp"
#include "db/iquery_executor.hpp"
#include "policy/policy_engine.hpp"
#include "server/irate_limiter.hpp"
#include <memory>

namespace sqlproxy {

// Forward declarations
class ClassifierRegistry;
class QueryRewriter;
class DatabaseRouter;
class PreparedStatementTracker;
class SqlInjectionDetector;
class AnomalyDetector;
class LineageTracker;
class ColumnEncryptor;

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
     * @brief Construct pipeline with components
     */
    Pipeline(
        std::shared_ptr<ISqlParser> parser,
        std::shared_ptr<PolicyEngine> policy_engine,
        std::shared_ptr<IRateLimiter> rate_limiter,
        std::shared_ptr<IQueryExecutor> executor,
        std::shared_ptr<ClassifierRegistry> classifier,
        std::shared_ptr<AuditEmitter> audit_emitter,
        std::shared_ptr<QueryRewriter> rewriter = nullptr,
        std::shared_ptr<DatabaseRouter> router = nullptr,
        std::shared_ptr<PreparedStatementTracker> prepared = nullptr,
        std::shared_ptr<SqlInjectionDetector> injection_detector = nullptr,
        std::shared_ptr<AnomalyDetector> anomaly_detector = nullptr,
        std::shared_ptr<LineageTracker> lineage_tracker = nullptr,
        std::shared_ptr<ColumnEncryptor> column_encryptor = nullptr
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
    std::shared_ptr<IRateLimiter> get_rate_limiter() const { return rate_limiter_; }

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
     * @brief Layer 4.5: Rewrite query (RLS + enforce_limit)
     */
    void rewrite_query(RequestContext& ctx);

    /**
     * @brief Layer 5.5: Apply column-level access control
     */
    void apply_column_policies(RequestContext& ctx);

    /**
     * @brief Layer 5.6: Apply data masking to allowed columns
     */
    void apply_masking(RequestContext& ctx);

    /**
     * @brief Build response from context
     */
    ProxyResponse build_response(const RequestContext& ctx);

    /**
     * @brief Handle PREPARE statement - parse inner SQL, register in tracker
     */
    void handle_prepare(RequestContext& ctx);

    /**
     * @brief Handle EXECUTE statement - look up cached parse info
     */
    void handle_execute(RequestContext& ctx);

    /**
     * @brief Handle DEALLOCATE statement - remove from tracker
     */
    void handle_deallocate(RequestContext& ctx);

    /**
     * @brief Layer 3.5: SQL injection detection (can block)
     */
    bool check_injection(RequestContext& ctx);

    /**
     * @brief Layer 3.7: Anomaly detection (informational, never blocks)
     */
    void check_anomaly(RequestContext& ctx);

    /**
     * @brief Layer 5.3: Decrypt encrypted columns (transparent)
     */
    void decrypt_columns(RequestContext& ctx);

    /**
     * @brief Layer 6.5: Record data lineage for PII columns
     */
    void record_lineage(RequestContext& ctx);

    const std::shared_ptr<ISqlParser> parser_;
    const std::shared_ptr<PolicyEngine> policy_engine_;
    const std::shared_ptr<IRateLimiter> rate_limiter_;
    const std::shared_ptr<IQueryExecutor> executor_;
    const std::shared_ptr<ClassifierRegistry> classifier_;
    const std::shared_ptr<AuditEmitter> audit_emitter_;
    const std::shared_ptr<QueryRewriter> rewriter_;
    const std::shared_ptr<DatabaseRouter> router_;
    const std::shared_ptr<PreparedStatementTracker> prepared_;
    const std::shared_ptr<SqlInjectionDetector> injection_detector_;
    const std::shared_ptr<AnomalyDetector> anomaly_detector_;
    const std::shared_ptr<LineageTracker> lineage_tracker_;
    const std::shared_ptr<ColumnEncryptor> column_encryptor_;
};

} // namespace sqlproxy
