#pragma once

#include <string>

namespace sqlproxy {

/**
 * @brief OpenAPI 3.0 spec and SwaggerUI handler
 *
 * Serves:
 * - GET /openapi.json — OpenAPI 3.0 specification
 * - GET /api/docs    — SwaggerUI HTML page
 */
class OpenAPIHandler {
public:
    /// Get OpenAPI 3.0 JSON specification string
    [[nodiscard]] static const std::string& get_spec_json();

    /// Get SwaggerUI HTML page (loads from CDN)
    [[nodiscard]] static const std::string& get_swagger_html();
};

} // namespace sqlproxy
