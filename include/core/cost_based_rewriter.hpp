#pragma once

#include "core/types.hpp"
#include "analyzer/sql_analyzer.hpp"
#include "analyzer/schema_cache.hpp"

#include <memory>
#include <string>

namespace sqlproxy {

class CostBasedRewriter {
public:
    struct Config {
        bool enabled = false;
        double cost_threshold = 50000.0;
        size_t max_columns_for_star = 20;
    };

    struct RewriteResult {
        bool rewritten = false;
        std::string new_sql;
        std::string rule_applied;
    };

    CostBasedRewriter();
    explicit CostBasedRewriter(Config config);

    [[nodiscard]] bool is_enabled() const { return config_.enabled; }

    void set_schema_cache(std::shared_ptr<SchemaCache> cache);

    [[nodiscard]] RewriteResult rewrite_if_expensive(
        const std::string& sql, const AnalysisResult& analysis) const;

private:
    [[nodiscard]] RewriteResult try_restrict_star_select(
        const std::string& sql, const AnalysisResult& analysis) const;

    [[nodiscard]] RewriteResult try_add_default_limit(
        const std::string& sql, const AnalysisResult& analysis) const;

    Config config_;
    std::shared_ptr<SchemaCache> schema_cache_;
};

} // namespace sqlproxy
