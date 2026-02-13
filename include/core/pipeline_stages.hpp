#pragma once

#include "core/pipeline_stage.hpp"
#include "core/pipeline_builder.hpp"
#include "core/types.hpp"
#include "core/utils.hpp"
#include "tracing/span.hpp"
#include <format>
#include <memory>

namespace sqlproxy {

// Forward declarations
class ISqlParser;
class DatabaseRouter;
class SQLAnalyzer;
class ResultCache;
class SqlInjectionDetector;
class AnomalyDetector;
class SqlFirewall;
class PolicyEngine;
class SchemaManager;
class QueryRewriter;
class CostBasedRewriter;
class QueryCostEstimator;
class DataResidencyEnforcer;

/**
 * @brief Base class providing access to pipeline components
 */
class ComponentStage : public IPipelineStage {
public:
    explicit ComponentStage(PipelineComponents& c) : c_(c) {}
protected:
    PipelineComponents& c_;
};

// ============================================================================
// Pre-Execute Stages (can BLOCK or CONTINUE)
// ============================================================================

class DataResidencyStage final : public ComponentStage {
public:
    using ComponentStage::ComponentStage;
    [[nodiscard]] Result process(RequestContext& ctx) override;
    [[nodiscard]] std::string_view name() const override { return "data_residency"; }
};

class RateLimitStage final : public ComponentStage {
public:
    using ComponentStage::ComponentStage;
    [[nodiscard]] Result process(RequestContext& ctx) override;
    [[nodiscard]] std::string_view name() const override { return "rate_limit"; }
};

class ParseStage final : public ComponentStage {
public:
    using ComponentStage::ComponentStage;
    [[nodiscard]] Result process(RequestContext& ctx) override;
    [[nodiscard]] std::string_view name() const override { return "parse"; }
};

class AnalyzeStage final : public ComponentStage {
public:
    using ComponentStage::ComponentStage;
    [[nodiscard]] Result process(RequestContext& ctx) override;
    [[nodiscard]] std::string_view name() const override { return "analyze"; }
};

class ResultCacheLookupStage final : public ComponentStage {
public:
    using ComponentStage::ComponentStage;
    [[nodiscard]] Result process(RequestContext& ctx) override;
    [[nodiscard]] std::string_view name() const override { return "result_cache_lookup"; }
};

class InjectionDetectionStage final : public ComponentStage {
public:
    using ComponentStage::ComponentStage;
    [[nodiscard]] Result process(RequestContext& ctx) override;
    [[nodiscard]] std::string_view name() const override { return "injection_detection"; }
};

class AnomalyDetectionStage final : public ComponentStage {
public:
    using ComponentStage::ComponentStage;
    [[nodiscard]] Result process(RequestContext& ctx) override;
    [[nodiscard]] std::string_view name() const override { return "anomaly_detection"; }
};

class FirewallStage final : public ComponentStage {
public:
    using ComponentStage::ComponentStage;
    [[nodiscard]] Result process(RequestContext& ctx) override;
    [[nodiscard]] std::string_view name() const override { return "firewall"; }
};

class PolicyStage final : public ComponentStage {
public:
    using ComponentStage::ComponentStage;
    [[nodiscard]] Result process(RequestContext& ctx) override;
    [[nodiscard]] std::string_view name() const override { return "policy"; }
};

class DdlInterceptStage final : public ComponentStage {
public:
    using ComponentStage::ComponentStage;
    [[nodiscard]] Result process(RequestContext& ctx) override;
    [[nodiscard]] std::string_view name() const override { return "ddl_intercept"; }
};

class RewriteStage final : public ComponentStage {
public:
    using ComponentStage::ComponentStage;
    [[nodiscard]] Result process(RequestContext& ctx) override;
    [[nodiscard]] std::string_view name() const override { return "rewrite"; }
};

class CostRewriteStage final : public ComponentStage {
public:
    using ComponentStage::ComponentStage;
    [[nodiscard]] Result process(RequestContext& ctx) override;
    [[nodiscard]] std::string_view name() const override { return "cost_rewrite"; }
};

class CostCheckStage final : public ComponentStage {
public:
    using ComponentStage::ComponentStage;
    [[nodiscard]] Result process(RequestContext& ctx) override;
    [[nodiscard]] std::string_view name() const override { return "cost_check"; }
};

} // namespace sqlproxy
