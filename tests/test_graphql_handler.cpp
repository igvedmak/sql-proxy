#include <catch2/catch_test_macros.hpp>
#include "server/graphql_handler.hpp"
#include "server/binary_rpc_server.hpp"

using namespace sqlproxy;

// ============================================================================
// GraphQL Parser
// ============================================================================

TEST_CASE("GraphQL: parse simple query", "[graphql]") {
    GraphQLHandler handler(nullptr);

    auto query = handler.parse("{ customers { id name email } }");
    REQUIRE(query.has_value());
    REQUIRE(query->table == "customers");
    REQUIRE(query->fields.size() == 3);
    REQUIRE(query->fields[0].name == "id");
    REQUIRE(query->fields[1].name == "name");
    REQUIRE(query->fields[2].name == "email");
    REQUIRE(query->where_clauses.empty());
    REQUIRE_FALSE(query->limit.has_value());
}

TEST_CASE("GraphQL: parse query with where clause", "[graphql]") {
    GraphQLHandler handler(nullptr);

    auto query = handler.parse(R"({ customers(where: {id: "1"}) { id name } })");
    REQUIRE(query.has_value());
    REQUIRE(query->table == "customers");
    REQUIRE(query->where_clauses.size() == 1);
    REQUIRE(query->where_clauses[0].first == "id");
    REQUIRE(query->where_clauses[0].second == "1");
}

TEST_CASE("GraphQL: parse query with multiple where clauses", "[graphql]") {
    GraphQLHandler handler(nullptr);

    auto query = handler.parse(R"({ users(where: {status: "active", role: "admin"}) { id name } })");
    REQUIRE(query.has_value());
    REQUIRE(query->where_clauses.size() == 2);
}

TEST_CASE("GraphQL: parse query with limit", "[graphql]") {
    GraphQLHandler handler(nullptr);

    auto query = handler.parse("{ orders(limit: 10) { id total } }");
    REQUIRE(query.has_value());
    REQUIRE(query->table == "orders");
    REQUIRE(query->limit.has_value());
    REQUIRE(*query->limit == 10);
}

TEST_CASE("GraphQL: parse query with limit and offset", "[graphql]") {
    GraphQLHandler handler(nullptr);

    auto query = handler.parse("{ orders(limit: 10, offset: 20) { id total } }");
    REQUIRE(query.has_value());
    REQUIRE(query->limit.has_value());
    REQUIRE(*query->limit == 10);
    REQUIRE(query->offset.has_value());
    REQUIRE(*query->offset == 20);
}

TEST_CASE("GraphQL: parse query with order_by", "[graphql]") {
    GraphQLHandler handler(nullptr);

    auto query = handler.parse(R"({ orders(order_by: "created_at", order: "desc") { id total } })");
    REQUIRE(query.has_value());
    REQUIRE(query->order_by == "created_at");
    REQUIRE(query->order_desc == true);
}

TEST_CASE("GraphQL: parse invalid query returns nullopt", "[graphql]") {
    GraphQLHandler handler(nullptr);

    REQUIRE_FALSE(handler.parse("").has_value());
    REQUIRE_FALSE(handler.parse("not a query").has_value());
    REQUIRE_FALSE(handler.parse("{ }").has_value());  // no table
}

TEST_CASE("GraphQL: parse query with 'query' keyword", "[graphql]") {
    GraphQLHandler handler(nullptr);

    auto query = handler.parse("query { customers { id } }");
    REQUIRE(query.has_value());
    REQUIRE(query->table == "customers");
    REQUIRE(query->fields.size() == 1);
}

// ============================================================================
// GraphQL to SQL translation
// ============================================================================

TEST_CASE("GraphQL: to_sql simple select", "[graphql]") {
    GraphQLHandler handler(nullptr);

    auto query = handler.parse("{ customers { id name email } }");
    REQUIRE(query.has_value());

    std::string sql = handler.to_sql(*query);
    REQUIRE(sql == "SELECT id, name, email FROM customers");
}

TEST_CASE("GraphQL: to_sql with where clause", "[graphql]") {
    GraphQLHandler handler(nullptr);

    auto query = handler.parse(R"({ customers(where: {id: "1"}) { id name } })");
    REQUIRE(query.has_value());

    std::string sql = handler.to_sql(*query);
    REQUIRE(sql == "SELECT id, name FROM customers WHERE id = '1'");
}

TEST_CASE("GraphQL: to_sql with limit", "[graphql]") {
    GraphQLHandler handler(nullptr);

    auto query = handler.parse("{ orders(limit: 5) { id } }");
    REQUIRE(query.has_value());

    std::string sql = handler.to_sql(*query);
    REQUIRE(sql == "SELECT id FROM orders LIMIT 5");
}

TEST_CASE("GraphQL: to_sql with all options", "[graphql]") {
    GraphQLHandler handler(nullptr);

    auto query = handler.parse(
        R"({ orders(where: {status: "active"}, order_by: "id", order: "desc", limit: 10, offset: 5) { id total } })");
    REQUIRE(query.has_value());

    std::string sql = handler.to_sql(*query);
    REQUIRE(sql.find("SELECT id, total FROM orders") != std::string::npos);
    REQUIRE(sql.find("WHERE status = 'active'") != std::string::npos);
    REQUIRE(sql.find("ORDER BY id DESC") != std::string::npos);
    REQUIRE(sql.find("LIMIT 10") != std::string::npos);
    REQUIRE(sql.find("OFFSET 5") != std::string::npos);
}

TEST_CASE("GraphQL: SQL injection prevention in where clause", "[graphql]") {
    GraphQLHandler handler(nullptr);

    auto query = handler.parse(R"({ users(where: {name: "'; DROP TABLE users;--"}) { id } })");
    REQUIRE(query.has_value());

    std::string sql = handler.to_sql(*query);
    // Single quotes should be escaped to double single quotes
    REQUIRE(sql.find("''") != std::string::npos);
    REQUIRE(sql.find("DROP TABLE") != std::string::npos); // still in value but escaped
}

// ============================================================================
// GraphQL config
// ============================================================================

TEST_CASE("GraphQLHandler: config defaults", "[graphql]") {
    GraphQLHandler handler(nullptr);
    REQUIRE(handler.config().enabled == false);
    REQUIRE(handler.config().endpoint == "/api/v1/graphql");
    REQUIRE(handler.config().max_query_depth == 5);
}

TEST_CASE("GraphQLHandler: custom config", "[graphql]") {
    GraphQLConfig config;
    config.enabled = true;
    config.endpoint = "/graphql";
    config.max_query_depth = 3;

    GraphQLHandler handler(nullptr, config);
    REQUIRE(handler.config().enabled == true);
    REQUIRE(handler.config().endpoint == "/graphql");
    REQUIRE(handler.config().max_query_depth == 3);
}

// ============================================================================
// Binary RPC types
// ============================================================================

TEST_CASE("BinaryRpc: message type constants", "[binary_rpc]") {
    REQUIRE(rpc::MSG_QUERY_REQUEST == 0x01);
    REQUIRE(rpc::MSG_QUERY_RESPONSE == 0x02);
    REQUIRE(rpc::MSG_ERROR == 0xFF);
}

TEST_CASE("BinaryRpc: config defaults", "[binary_rpc]") {
    BinaryRpcConfig config;
    REQUIRE(config.enabled == false);
    REQUIRE(config.host == "0.0.0.0");
    REQUIRE(config.port == 9090);
    REQUIRE(config.max_connections == 50);
}

TEST_CASE("BinaryRpc: BinaryQueryRequest struct", "[binary_rpc]") {
    BinaryQueryRequest req;
    req.user = "testuser";
    req.database = "testdb";
    req.sql = "SELECT 1";

    REQUIRE(req.user == "testuser");
    REQUIRE(req.database == "testdb");
    REQUIRE(req.sql == "SELECT 1");
}
