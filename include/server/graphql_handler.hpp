#pragma once

#include "core/pipeline.hpp"
#include "server/http_server.hpp"  // UserInfo
#include <memory>
#include <string>
#include <vector>
#include <optional>

namespace sqlproxy {

struct GraphQLConfig {
    bool enabled = false;
    std::string endpoint = "/api/v1/graphql";
    uint32_t max_query_depth = 5;
    bool mutations_enabled = false;
};

// Parsed GraphQL field selection
struct GraphQLField {
    std::string name;
    std::vector<GraphQLField> sub_fields;    // Nested selections
};

// Parsed GraphQL query
struct GraphQLQuery {
    std::string table;                        // Root table name
    std::vector<GraphQLField> fields;         // Selected fields
    std::vector<std::pair<std::string, std::string>> where_clauses;  // key=value filters
    std::optional<int> limit;
    std::optional<int> offset;
    std::string order_by;
    bool order_desc = false;
};

// Parsed GraphQL mutation
enum class MutationType { INSERT, UPDATE, DELETE };

struct GraphQLMutation {
    MutationType type;
    std::string table;
    std::vector<std::pair<std::string, std::string>> data;            // For INSERT/UPDATE SET
    std::vector<std::pair<std::string, std::string>> where_clauses;   // For UPDATE/DELETE WHERE
    std::vector<GraphQLField> returning_fields;                       // RETURNING clause
};

class GraphQLHandler {
public:
    explicit GraphQLHandler(std::shared_ptr<Pipeline> pipeline,
                            const GraphQLConfig& config = {});

    // Parse GraphQL query string into structured representation
    [[nodiscard]] std::optional<GraphQLQuery> parse(const std::string& query) const;

    // Parse GraphQL mutation
    [[nodiscard]] std::optional<GraphQLMutation> parse_mutation(const std::string& query) const;

    // Translate parsed GraphQL query to SQL
    [[nodiscard]] std::string to_sql(const GraphQLQuery& gql) const;

    // Translate parsed mutation to SQL
    [[nodiscard]] std::string mutation_to_sql(const GraphQLMutation& mutation) const;

    // Execute a GraphQL query/mutation and return JSON response
    [[nodiscard]] std::string execute(const std::string& graphql_query,
                                       const std::string& user,
                                       const std::vector<std::string>& roles,
                                       const std::string& database) const;

    [[nodiscard]] const GraphQLConfig& config() const { return config_; }

private:
    // Escape SQL string value (prevent injection)
    [[nodiscard]] static std::string escape_sql_value(const std::string& val);

    // Build GraphQL-format JSON response from ProxyResponse
    [[nodiscard]] static std::string build_graphql_response(
        const ProxyResponse& response, const std::string& table);

    // Parse key-value pairs from argument string: {k1: "v1", k2: "v2"}
    [[nodiscard]] static std::vector<std::pair<std::string, std::string>>
    parse_object_arg(const std::string& args_str, size_t& pos);

    // Parse field list from: { field1 field2 }
    [[nodiscard]] static std::vector<GraphQLField>
    parse_field_list(std::string_view& sv);

    std::shared_ptr<Pipeline> pipeline_;
    GraphQLConfig config_;
};

} // namespace sqlproxy
