#include <catch2/catch_test_macros.hpp>
#include "server/wire_copy.hpp"

using namespace sqlproxy;
using namespace sqlproxy::copy;

TEST_CASE("parse_copy_statement - COPY TO STDOUT", "[wire_copy]") {
    auto result = parse_copy_statement("COPY customers TO STDOUT");
    REQUIRE(result.has_value());
    REQUIRE(result->table_name == "customers");
    REQUIRE(result->direction == CopyStatement::TO_STDOUT);
    REQUIRE(result->format == 0);
}

TEST_CASE("parse_copy_statement - COPY FROM STDIN", "[wire_copy]") {
    auto result = parse_copy_statement("COPY orders FROM STDIN");
    REQUIRE(result.has_value());
    REQUIRE(result->table_name == "orders");
    REQUIRE(result->direction == CopyStatement::FROM_STDIN);
    REQUIRE(result->format == 0);
}

TEST_CASE("parse_copy_statement - COPY with columns", "[wire_copy]") {
    auto result = parse_copy_statement("COPY customers (id, name, email) TO STDOUT");
    REQUIRE(result.has_value());
    REQUIRE(result->table_name == "customers");
    REQUIRE(result->direction == CopyStatement::TO_STDOUT);
}

TEST_CASE("parse_copy_statement - COPY with BINARY format", "[wire_copy]") {
    auto result = parse_copy_statement("COPY customers TO STDOUT WITH (FORMAT BINARY)");
    REQUIRE(result.has_value());
    REQUIRE(result->format == 1);
}

TEST_CASE("parse_copy_statement - COPY FROM file", "[wire_copy]") {
    auto result = parse_copy_statement("COPY customers FROM '/tmp/data.csv'");
    REQUIRE(result.has_value());
    REQUIRE(result->direction == CopyStatement::FROM_FILE);
}

TEST_CASE("parse_copy_statement - COPY TO file", "[wire_copy]") {
    auto result = parse_copy_statement("COPY customers TO '/tmp/output.csv'");
    REQUIRE(result.has_value());
    REQUIRE(result->direction == CopyStatement::TO_FILE);
}

TEST_CASE("parse_copy_statement - not a COPY", "[wire_copy]") {
    auto result = parse_copy_statement("SELECT * FROM customers");
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("parse_copy_statement - empty input", "[wire_copy]") {
    auto result = parse_copy_statement("");
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("parse_copy_statement - case insensitive", "[wire_copy]") {
    auto result = parse_copy_statement("copy Customers from stdin");
    REQUIRE(result.has_value());
    REQUIRE(result->table_name == "Customers");
    REQUIRE(result->direction == CopyStatement::FROM_STDIN);
}

TEST_CASE("WireCopyWriter - copy_in_response", "[wire_copy]") {
    auto msg = WireCopyWriter::copy_in_response(0, 3);
    REQUIRE(msg[0] == static_cast<uint8_t>(wire::MSG_COPY_IN_RESPONSE));
    // Should have type byte + 4 length bytes + format byte + 2 num_columns + 3*2 per-col formats
    REQUIRE(msg.size() > 5);
}

TEST_CASE("WireCopyWriter - copy_out_response", "[wire_copy]") {
    auto msg = WireCopyWriter::copy_out_response(0, 2);
    REQUIRE(msg[0] == static_cast<uint8_t>(wire::MSG_COPY_OUT_RESPONSE));
    REQUIRE(msg.size() > 5);
}

TEST_CASE("WireCopyWriter - copy_data", "[wire_copy]") {
    std::string data = "hello\tworld\n";
    auto msg = WireCopyWriter::copy_data(data);
    REQUIRE(msg[0] == static_cast<uint8_t>(wire::MSG_COPY_DATA));
    // Verify data is in the payload
    std::string payload(msg.begin() + 5, msg.end());
    REQUIRE(payload == data);
}

TEST_CASE("WireCopyWriter - copy_done", "[wire_copy]") {
    auto msg = WireCopyWriter::copy_done();
    REQUIRE(msg[0] == static_cast<uint8_t>(wire::MSG_COPY_DONE));
    REQUIRE(msg.size() == 5);
}

TEST_CASE("WireCopyWriter - copy_fail", "[wire_copy]") {
    auto msg = WireCopyWriter::copy_fail("test error");
    REQUIRE(msg[0] == static_cast<uint8_t>(wire::MSG_COPY_FAIL));
    // Should contain the error string (null-terminated)
    REQUIRE(msg.size() > 5);
}
