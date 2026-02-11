#include "server/graphql_handler.hpp"
#include "core/utils.hpp"

#include <algorithm>
#include <format>
#include <sstream>

namespace sqlproxy {

GraphQLHandler::GraphQLHandler(std::shared_ptr<Pipeline> pipeline,
                               const GraphQLConfig& config)
    : pipeline_(std::move(pipeline)), config_(config) {}

std::optional<GraphQLQuery> GraphQLHandler::parse(const std::string& query) const {
    // Simple recursive-descent parser for:
    // { table_name(where: {key: "val"}, limit: N, offset: N, order_by: "col", order: "desc") { field1 field2 } }

    GraphQLQuery gql;
    std::string_view sv(query);

    // Skip leading whitespace and optional "query" keyword
    auto skip_ws = [&sv]() {
        while (!sv.empty() && std::isspace(sv.front())) sv.remove_prefix(1);
    };

    skip_ws();

    // Skip "query" keyword and optional name
    if (sv.starts_with("query")) {
        sv.remove_prefix(5);
        skip_ws();
        // Skip optional query name
        while (!sv.empty() && !std::isspace(sv.front()) && sv.front() != '{') {
            sv.remove_prefix(1);
        }
        skip_ws();
    }

    // Expect opening '{'
    if (sv.empty() || sv.front() != '{') return std::nullopt;
    sv.remove_prefix(1);
    skip_ws();

    // Parse table name
    size_t name_end = 0;
    while (name_end < sv.size() && !std::isspace(sv[name_end]) &&
           sv[name_end] != '(' && sv[name_end] != '{') {
        ++name_end;
    }
    if (name_end == 0) return std::nullopt;
    gql.table = std::string(sv.substr(0, name_end));
    sv.remove_prefix(name_end);
    skip_ws();

    // Parse optional arguments (where, limit, offset, order_by, order)
    if (!sv.empty() && sv.front() == '(') {
        sv.remove_prefix(1); // skip '('

        // Find matching ')'
        int depth = 1;
        size_t end = 0;
        bool in_str = false;
        for (; end < sv.size() && depth > 0; ++end) {
            if (sv[end] == '"') in_str = !in_str;
            if (!in_str) {
                if (sv[end] == '(') ++depth;
                if (sv[end] == ')') --depth;
            }
        }
        std::string args_str(sv.substr(0, end > 0 ? end - 1 : 0));
        sv.remove_prefix(end);

        // Parse key: value pairs from args
        // where: {id: "1", name: "test"}, limit: 10, offset: 5
        size_t pos = 0;
        while (pos < args_str.size()) {
            // Skip whitespace and commas
            while (pos < args_str.size() && (std::isspace(args_str[pos]) || args_str[pos] == ',')) ++pos;
            if (pos >= args_str.size()) break;

            // Read key
            size_t key_start = pos;
            while (pos < args_str.size() && args_str[pos] != ':') ++pos;
            std::string key(args_str, key_start, pos - key_start);
            // Trim key
            while (!key.empty() && std::isspace(key.back())) key.pop_back();
            while (!key.empty() && std::isspace(key.front())) key.erase(key.begin());
            if (pos < args_str.size()) ++pos; // skip ':'

            // Skip whitespace
            while (pos < args_str.size() && std::isspace(args_str[pos])) ++pos;

            if (key == "where") {
                // Parse where: {key: "val", ...}
                if (pos < args_str.size() && args_str[pos] == '{') {
                    ++pos;
                    // Find matching '}'
                    size_t brace_start = pos;
                    int bd = 1;
                    while (pos < args_str.size() && bd > 0) {
                        if (args_str[pos] == '{') ++bd;
                        if (args_str[pos] == '}') --bd;
                        ++pos;
                    }
                    std::string where_str(args_str, brace_start, pos > 0 ? pos - brace_start - 1 : 0);

                    // Parse key: "value" pairs
                    size_t wp = 0;
                    while (wp < where_str.size()) {
                        while (wp < where_str.size() && (std::isspace(where_str[wp]) || where_str[wp] == ',')) ++wp;
                        if (wp >= where_str.size()) break;

                        size_t wk_start = wp;
                        while (wp < where_str.size() && where_str[wp] != ':') ++wp;
                        std::string wk(where_str, wk_start, wp - wk_start);
                        while (!wk.empty() && std::isspace(wk.back())) wk.pop_back();
                        while (!wk.empty() && std::isspace(wk.front())) wk.erase(wk.begin());
                        if (wp < where_str.size()) ++wp;

                        while (wp < where_str.size() && std::isspace(where_str[wp])) ++wp;

                        std::string wv;
                        if (wp < where_str.size() && where_str[wp] == '"') {
                            ++wp;
                            size_t wv_start = wp;
                            while (wp < where_str.size() && where_str[wp] != '"') ++wp;
                            wv = std::string(where_str, wv_start, wp - wv_start);
                            if (wp < where_str.size()) ++wp;
                        } else {
                            size_t wv_start = wp;
                            while (wp < where_str.size() && !std::isspace(where_str[wp]) &&
                                   where_str[wp] != ',' && where_str[wp] != '}') ++wp;
                            wv = std::string(where_str, wv_start, wp - wv_start);
                        }

                        if (!wk.empty()) {
                            gql.where_clauses.emplace_back(std::move(wk), std::move(wv));
                        }
                    }
                }
            } else {
                // Read value (number or quoted string)
                std::string val;
                if (pos < args_str.size() && args_str[pos] == '"') {
                    ++pos;
                    size_t val_start = pos;
                    while (pos < args_str.size() && args_str[pos] != '"') ++pos;
                    val = std::string(args_str, val_start, pos - val_start);
                    if (pos < args_str.size()) ++pos;
                } else {
                    size_t val_start = pos;
                    while (pos < args_str.size() && !std::isspace(args_str[pos]) &&
                           args_str[pos] != ',' && args_str[pos] != ')') ++pos;
                    val = std::string(args_str, val_start, pos - val_start);
                }

                if (key == "limit") {
                    gql.limit = utils::parse_int<int>(val);
                } else if (key == "offset") {
                    gql.offset = utils::parse_int<int>(val);
                } else if (key == "order_by") {
                    gql.order_by = val;
                } else if (key == "order") {
                    gql.order_desc = (val == "desc" || val == "DESC");
                }
            }
        }
    }

    skip_ws();

    // Parse field selection { field1 field2 }
    if (sv.empty() || sv.front() != '{') return std::nullopt;
    sv.remove_prefix(1);
    skip_ws();

    while (!sv.empty() && sv.front() != '}') {
        size_t field_end = 0;
        while (field_end < sv.size() && !std::isspace(sv[field_end]) &&
               sv[field_end] != '}' && sv[field_end] != '{') {
            ++field_end;
        }
        if (field_end > 0) {
            GraphQLField field;
            field.name = std::string(sv.substr(0, field_end));
            gql.fields.emplace_back(std::move(field));
            sv.remove_prefix(field_end);
        }
        skip_ws();
    }

    if (gql.fields.empty()) return std::nullopt;

    return gql;
}

std::string GraphQLHandler::to_sql(const GraphQLQuery& gql) const {
    std::string sql = "SELECT ";

    // Columns
    for (size_t i = 0; i < gql.fields.size(); ++i) {
        if (i > 0) sql += ", ";
        sql += gql.fields[i].name;
    }

    sql += " FROM ";
    sql += gql.table;

    // WHERE
    if (!gql.where_clauses.empty()) {
        sql += " WHERE ";
        for (size_t i = 0; i < gql.where_clauses.size(); ++i) {
            if (i > 0) sql += " AND ";
            sql += gql.where_clauses[i].first;
            sql += " = '";
            sql += escape_sql_value(gql.where_clauses[i].second);
            sql += "'";
        }
    }

    // ORDER BY
    if (!gql.order_by.empty()) {
        sql += " ORDER BY ";
        sql += gql.order_by;
        if (gql.order_desc) sql += " DESC";
    }

    // LIMIT
    if (gql.limit.has_value()) {
        sql += std::format(" LIMIT {}", *gql.limit);
    }

    // OFFSET
    if (gql.offset.has_value()) {
        sql += std::format(" OFFSET {}", *gql.offset);
    }

    return sql;
}

std::string GraphQLHandler::execute(const std::string& graphql_query,
                                     const std::string& user,
                                     const std::vector<std::string>& roles,
                                     const std::string& database) const {
    const auto gql = parse(graphql_query);
    if (!gql) {
        return R"({"errors":[{"message":"Failed to parse GraphQL query"}]})";
    }

    const std::string sql = to_sql(*gql);

    ProxyRequest request;
    request.user = user;
    request.roles = roles;
    request.sql = sql;
    request.database = database;

    const auto response = pipeline_->execute(request);

    return build_graphql_response(response, gql->table);
}

std::string GraphQLHandler::escape_sql_value(const std::string& val) {
    std::string escaped;
    escaped.reserve(val.size());
    for (const char c : val) {
        if (c == '\'') escaped += "''";
        else if (c == '\\') escaped += "\\\\";
        else escaped += c;
    }
    return escaped;
}

std::string GraphQLHandler::build_graphql_response(
    const ProxyResponse& response, const std::string& table) {
    if (!response.success) {
        return std::format(R"({{"errors":[{{"message":"{}"}}]}})", response.error_message);
    }

    if (!response.result.has_value()) {
        return "{\"data\":{\"" + table + "\":[]}}";

    }

    const auto& result = *response.result;
    std::string json = std::format(R"({{"data":{{"{}":[ )", table);

    for (size_t i = 0; i < result.rows.size(); ++i) {
        if (i > 0) json += ",";
        json += "{";
        for (size_t j = 0; j < result.column_names.size() && j < result.rows[i].size(); ++j) {
            if (j > 0) json += ",";
            json += std::format(R"("{}":"{}")", result.column_names[j], result.rows[i][j]);
        }
        json += "}";
    }

    json += "]}}}";
    return json;
}

} // namespace sqlproxy
