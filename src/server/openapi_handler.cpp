#include "server/openapi_handler.hpp"

namespace sqlproxy {

const std::string& OpenAPIHandler::get_spec_json() {
    static const std::string spec = R"JSON({
  "openapi": "3.0.3",
  "info": {
    "title": "SQL Proxy API",
    "description": "High-performance SQL proxy with policy-driven access control, PII classification, data masking, encryption, and audit logging.",
    "version": "2.0.0",
    "license": { "name": "Proprietary" }
  },
  "servers": [
    { "url": "http://localhost:8080", "description": "Local development" }
  ],
  "tags": [
    { "name": "Query", "description": "SQL query execution" },
    { "name": "Health", "description": "Health checks and readiness" },
    { "name": "Metrics", "description": "Prometheus metrics" },
    { "name": "Admin", "description": "Administrative endpoints" },
    { "name": "Compliance", "description": "Compliance and governance" },
    { "name": "Schema", "description": "Schema management" },
    { "name": "Dashboard", "description": "Admin dashboard API" },
    { "name": "Docs", "description": "API documentation" }
  ],
  "paths": {
    "/api/v1/query": {
      "post": {
        "tags": ["Query"],
        "summary": "Execute SQL query",
        "description": "Execute a SQL query through the full proxy pipeline (rate limit, parse, policy, execute, classify, audit).",
        "operationId": "executeQuery",
        "security": [{"bearerAuth": []}, {"apiKeyBody": []}],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": { "$ref": "#/components/schemas/QueryRequest" },
              "example": {
                "user": "analyst",
                "database": "testdb",
                "sql": "SELECT id, name, email FROM customers LIMIT 5"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Query executed successfully",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/QueryResponse" }
              }
            },
            "headers": {
              "X-RateLimit-Remaining": { "schema": { "type": "integer" }, "description": "Remaining rate limit tokens" },
              "X-RateLimit-Level": { "schema": { "type": "string" }, "description": "Rate limit level that was checked" },
              "traceparent": { "schema": { "type": "string" }, "description": "W3C Trace Context header" }
            }
          },
          "400": { "description": "Invalid request (missing fields, SQL too long)", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "401": { "description": "Authentication failed", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "403": { "description": "Access denied by policy", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "429": { "description": "Rate limited", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } }, "headers": { "Retry-After": { "schema": { "type": "integer" }, "description": "Seconds to wait before retrying" } } },
          "500": { "description": "Internal server error", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/api/v1/query/dry-run": {
      "post": {
        "tags": ["Query"],
        "summary": "Dry-run SQL query",
        "description": "Evaluate policy and parse query without executing. Returns what would happen.",
        "operationId": "dryRunQuery",
        "security": [{"bearerAuth": []}, {"apiKeyBody": []}],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": { "$ref": "#/components/schemas/QueryRequest" }
            }
          }
        },
        "responses": {
          "200": { "description": "Dry-run result", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/QueryResponse" } } } },
          "400": { "description": "Invalid request" },
          "401": { "description": "Authentication failed" },
          "403": { "description": "Access denied by policy" }
        }
      }
    },
    "/health": {
      "get": {
        "tags": ["Health"],
        "summary": "Health check",
        "description": "Returns service health status. Supports depth levels via query parameter.",
        "operationId": "healthCheck",
        "parameters": [
          {
            "name": "level",
            "in": "query",
            "required": false,
            "schema": { "type": "string", "enum": ["shallow", "deep", "readiness"] },
            "description": "Health check depth level"
          }
        ],
        "responses": {
          "200": {
            "description": "Service is healthy",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/HealthResponse" }
              }
            }
          },
          "503": { "description": "Service is unhealthy" }
        }
      }
    },
    "/metrics": {
      "get": {
        "tags": ["Metrics"],
        "summary": "Prometheus metrics",
        "description": "Returns metrics in Prometheus text exposition format.",
        "operationId": "getMetrics",
        "responses": {
          "200": {
            "description": "Metrics in Prometheus format",
            "content": { "text/plain": { "schema": { "type": "string" } } }
          }
        }
      }
    },
    "/policies/reload": {
      "post": {
        "tags": ["Admin"],
        "summary": "Reload policies",
        "description": "Hot-reload policies from configuration file. Requires admin authentication.",
        "operationId": "reloadPolicies",
        "security": [{"bearerAuth": []}],
        "responses": {
          "200": { "description": "Policies reloaded successfully" },
          "401": { "description": "Admin authentication required" }
        }
      }
    },
    "/api/v1/config/validate": {
      "post": {
        "tags": ["Admin"],
        "summary": "Validate configuration",
        "description": "Validate a TOML configuration string without applying it.",
        "operationId": "validateConfig",
        "security": [{"bearerAuth": []}],
        "requestBody": {
          "required": true,
          "content": { "text/plain": { "schema": { "type": "string" } } }
        },
        "responses": {
          "200": { "description": "Configuration is valid" },
          "400": { "description": "Configuration is invalid" },
          "401": { "description": "Admin authentication required" }
        }
      }
    },
    "/api/v1/compliance/pii-report": {
      "get": {
        "tags": ["Compliance"],
        "summary": "PII detection report",
        "description": "Returns a report of PII detected across queries.",
        "operationId": "getPiiReport",
        "security": [{"bearerAuth": []}],
        "responses": {
          "200": { "description": "PII report", "content": { "application/json": { "schema": { "type": "object" } } } },
          "401": { "description": "Admin authentication required" }
        }
      }
    },
    "/api/v1/compliance/security-summary": {
      "get": {
        "tags": ["Compliance"],
        "summary": "Security summary",
        "description": "Returns security posture summary including injection attempts and anomalies.",
        "operationId": "getSecuritySummary",
        "security": [{"bearerAuth": []}],
        "responses": {
          "200": { "description": "Security summary", "content": { "application/json": { "schema": { "type": "object" } } } },
          "401": { "description": "Admin authentication required" }
        }
      }
    },
    "/api/v1/compliance/lineage": {
      "get": {
        "tags": ["Compliance"],
        "summary": "Data lineage",
        "description": "Returns data lineage tracking records for PII columns.",
        "operationId": "getLineage",
        "security": [{"bearerAuth": []}],
        "responses": {
          "200": { "description": "Lineage records", "content": { "application/json": { "schema": { "type": "object" } } } },
          "401": { "description": "Admin authentication required" }
        }
      }
    },
    "/api/v1/compliance/data-subject-access": {
      "get": {
        "tags": ["Compliance"],
        "summary": "GDPR data subject access (Article 15)",
        "description": "Returns all data access records for a specific user (GDPR Article 15 compliance).",
        "operationId": "getDataSubjectAccess",
        "security": [{"bearerAuth": []}],
        "parameters": [
          { "name": "user", "in": "query", "required": true, "schema": { "type": "string" }, "description": "Data subject username" }
        ],
        "responses": {
          "200": { "description": "Data subject access report", "content": { "application/json": { "schema": { "type": "object" } } } },
          "400": { "description": "Missing user parameter" },
          "401": { "description": "Admin authentication required" }
        }
      }
    },
    "/api/v1/schema/drift": {
      "get": {
        "tags": ["Schema"],
        "summary": "Schema drift detection",
        "description": "Returns detected schema drift events (unauthorized changes).",
        "operationId": "getSchemaDrift",
        "security": [{"bearerAuth": []}],
        "responses": {
          "200": { "description": "Drift events", "content": { "application/json": { "schema": { "type": "object" } } } },
          "401": { "description": "Admin authentication required" }
        }
      }
    },
    "/api/v1/schema/history": {
      "get": {
        "tags": ["Schema"],
        "summary": "Schema change history",
        "description": "Returns history of DDL schema changes.",
        "operationId": "getSchemaHistory",
        "security": [{"bearerAuth": []}],
        "responses": {
          "200": { "description": "Schema change history", "content": { "application/json": { "schema": { "type": "object" } } } },
          "401": { "description": "Admin authentication required" }
        }
      }
    },
    "/api/v1/schema/pending": {
      "get": {
        "tags": ["Schema"],
        "summary": "Pending DDL approvals",
        "description": "Returns DDL changes pending approval.",
        "operationId": "getPendingApprovals",
        "security": [{"bearerAuth": []}],
        "responses": {
          "200": { "description": "Pending DDL changes", "content": { "application/json": { "schema": { "type": "object" } } } },
          "401": { "description": "Admin authentication required" }
        }
      }
    },
    "/api/v1/schema/approve": {
      "post": {
        "tags": ["Schema"],
        "summary": "Approve DDL change",
        "description": "Approve a pending DDL schema change.",
        "operationId": "approveDdl",
        "security": [{"bearerAuth": []}],
        "requestBody": {
          "required": true,
          "content": { "application/json": { "schema": { "type": "object", "properties": { "change_id": { "type": "string" } }, "required": ["change_id"] } } }
        },
        "responses": {
          "200": { "description": "Change approved" },
          "401": { "description": "Admin authentication required" }
        }
      }
    },
    "/api/v1/schema/reject": {
      "post": {
        "tags": ["Schema"],
        "summary": "Reject DDL change",
        "operationId": "rejectDdl",
        "security": [{"bearerAuth": []}],
        "requestBody": {
          "required": true,
          "content": { "application/json": { "schema": { "type": "object", "properties": { "change_id": { "type": "string" } }, "required": ["change_id"] } } }
        },
        "responses": {
          "200": { "description": "Change rejected" },
          "401": { "description": "Admin authentication required" }
        }
      }
    },
    "/api/v1/slow-queries": {
      "get": {
        "tags": ["Admin"],
        "summary": "Slow query log",
        "description": "Returns recent slow queries exceeding the configured threshold.",
        "operationId": "getSlowQueries",
        "security": [{"bearerAuth": []}],
        "responses": {
          "200": { "description": "Slow queries", "content": { "application/json": { "schema": { "type": "object" } } } },
          "401": { "description": "Admin authentication required" }
        }
      }
    },
    "/api/v1/circuit-breakers": {
      "get": {
        "tags": ["Admin"],
        "summary": "Circuit breaker status",
        "description": "Returns current circuit breaker state for all databases.",
        "operationId": "getCircuitBreakers",
        "security": [{"bearerAuth": []}],
        "responses": {
          "200": { "description": "Circuit breaker states", "content": { "application/json": { "schema": { "type": "object" } } } },
          "401": { "description": "Admin authentication required" }
        }
      }
    },
    "/api/v1/graphql": {
      "post": {
        "tags": ["Query"],
        "summary": "GraphQL endpoint",
        "description": "Execute GraphQL queries (translated to SQL internally).",
        "operationId": "executeGraphQL",
        "security": [{"bearerAuth": []}],
        "requestBody": {
          "required": true,
          "content": { "application/json": { "schema": { "type": "object", "properties": { "query": { "type": "string" }, "variables": { "type": "object" } }, "required": ["query"] } } }
        },
        "responses": {
          "200": { "description": "GraphQL response", "content": { "application/json": { "schema": { "type": "object" } } } },
          "400": { "description": "Invalid GraphQL query" }
        }
      }
    },
    "/openapi.json": {
      "get": {
        "tags": ["Docs"],
        "summary": "OpenAPI specification",
        "description": "Returns this OpenAPI 3.0 specification as JSON.",
        "operationId": "getOpenApiSpec",
        "responses": {
          "200": { "description": "OpenAPI 3.0 JSON spec", "content": { "application/json": { "schema": { "type": "object" } } } }
        }
      }
    },
    "/api/docs": {
      "get": {
        "tags": ["Docs"],
        "summary": "Swagger UI",
        "description": "Interactive API documentation using Swagger UI.",
        "operationId": "getSwaggerUi",
        "responses": {
          "200": { "description": "Swagger UI HTML page", "content": { "text/html": { "schema": { "type": "string" } } } }
        }
      }
    },
    "/dashboard/api/stats": {
      "get": {
        "tags": ["Dashboard"],
        "summary": "Dashboard statistics",
        "description": "Returns real-time proxy statistics for the admin dashboard.",
        "operationId": "getDashboardStats",
        "security": [{"bearerAuth": []}],
        "responses": {
          "200": { "description": "Dashboard stats JSON" },
          "401": { "description": "Admin authentication required" }
        }
      }
    },
    "/dashboard/api/policies": {
      "get": {
        "tags": ["Dashboard"],
        "summary": "List policies",
        "operationId": "getDashboardPolicies",
        "security": [{"bearerAuth": []}],
        "responses": {
          "200": { "description": "Policy list" },
          "401": { "description": "Admin authentication required" }
        }
      }
    },
    "/dashboard/api/users": {
      "get": {
        "tags": ["Dashboard"],
        "summary": "List users",
        "operationId": "getDashboardUsers",
        "security": [{"bearerAuth": []}],
        "responses": {
          "200": { "description": "User list" },
          "401": { "description": "Admin authentication required" }
        }
      }
    },
    "/dashboard/api/alerts": {
      "get": {
        "tags": ["Dashboard"],
        "summary": "List alerts",
        "operationId": "getDashboardAlerts",
        "security": [{"bearerAuth": []}],
        "responses": {
          "200": { "description": "Alert list" },
          "401": { "description": "Admin authentication required" }
        }
      }
    }
  },
  "components": {
    "schemas": {
      "QueryRequest": {
        "type": "object",
        "required": ["sql"],
        "properties": {
          "user": { "type": "string", "description": "Username (alternative to Bearer token auth)" },
          "database": { "type": "string", "description": "Target database name", "default": "testdb" },
          "sql": { "type": "string", "description": "SQL query to execute", "maxLength": 102400 },
          "priority": { "type": "string", "enum": ["high", "normal", "low", "background"], "default": "normal", "description": "Request priority tier" },
          "traceparent": { "type": "string", "description": "W3C Trace Context traceparent header" },
          "tracestate": { "type": "string", "description": "W3C Trace Context tracestate header" }
        }
      },
      "QueryResponse": {
        "type": "object",
        "properties": {
          "success": { "type": "boolean" },
          "request_id": { "type": "string", "format": "uuid" },
          "audit_id": { "type": "string", "format": "uuid" },
          "error_code": { "type": "string" },
          "error_message": { "type": "string" },
          "data": {
            "type": "object",
            "properties": {
              "columns": { "type": "array", "items": { "type": "string" } },
              "rows": { "type": "array", "items": { "type": "array", "items": { "type": "string" } } },
              "row_count": { "type": "integer" }
            }
          },
          "classifications": { "type": "object", "additionalProperties": { "type": "string" } },
          "execution_time_us": { "type": "integer" },
          "policy_decision": { "type": "string", "enum": ["ALLOW", "BLOCK"] },
          "matched_policy": { "type": "string" },
          "masked_columns": { "type": "array", "items": { "type": "string" } },
          "blocked_columns": { "type": "array", "items": { "type": "string" } },
          "dry_run": { "type": "boolean" },
          "traceparent": { "type": "string" }
        }
      },
      "HealthResponse": {
        "type": "object",
        "properties": {
          "status": { "type": "string", "enum": ["healthy", "degraded", "unhealthy"] },
          "checks": { "type": "object" }
        }
      },
      "ErrorResponse": {
        "type": "object",
        "properties": {
          "success": { "type": "boolean", "example": false },
          "error_code": { "type": "string" },
          "error_message": { "type": "string" }
        }
      }
    },
    "securitySchemes": {
      "bearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "description": "API key or admin token as Bearer token"
      },
      "apiKeyBody": {
        "type": "apiKey",
        "in": "header",
        "name": "Authorization",
        "description": "API key in Authorization header"
      }
    }
  }
})JSON";
    return spec;
}

const std::string& OpenAPIHandler::get_swagger_html() {
    static const std::string html = R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Proxy API — Swagger UI</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        SwaggerUIBundle({
            url: '/openapi.json',
            dom_id: '#swagger-ui',
            presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
            layout: 'StandaloneLayout'
        });
    </script>
</body>
</html>)HTML";
    return html;
}

} // namespace sqlproxy
