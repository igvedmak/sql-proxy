#include "core/pipeline_builder.hpp"
#include "core/pipeline.hpp"
#include <stdexcept>

namespace sqlproxy {

std::shared_ptr<Pipeline> PipelineBuilder::build() {
    if (!c_.parser) throw std::runtime_error("PipelineBuilder: parser is required");
    if (!c_.policy_engine) throw std::runtime_error("PipelineBuilder: policy_engine is required");
    if (!c_.rate_limiter) throw std::runtime_error("PipelineBuilder: rate_limiter is required");
    if (!c_.executor) throw std::runtime_error("PipelineBuilder: executor is required");
    if (!c_.audit_emitter) throw std::runtime_error("PipelineBuilder: audit_emitter is required");

    return std::make_shared<Pipeline>(std::move(c_));
}

} // namespace sqlproxy
