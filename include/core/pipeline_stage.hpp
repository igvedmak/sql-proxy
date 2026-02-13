#pragma once

#include "core/request_context.hpp"
#include <string_view>

namespace sqlproxy {

/**
 * @brief Abstract pipeline stage interface
 *
 * Each stage in the request pipeline implements this interface.
 * Stages are composed into a chain and executed sequentially.
 *
 * Result semantics:
 * - CONTINUE:      Stage passed, proceed to next stage
 * - BLOCK:         Stage rejected request, emit audit + return error response
 * - SHORT_CIRCUIT: Stage handled request fully (e.g. cache hit), return response directly
 */
class IPipelineStage {
public:
    virtual ~IPipelineStage() = default;

    enum class Result { CONTINUE, BLOCK, SHORT_CIRCUIT };

    /**
     * @brief Process request through this stage
     * @param ctx Mutable request context
     * @return Stage result determining pipeline flow
     */
    [[nodiscard]] virtual Result process(RequestContext& ctx) = 0;

    /**
     * @brief Human-readable stage name for tracing/logging
     */
    [[nodiscard]] virtual std::string_view name() const = 0;
};

} // namespace sqlproxy
