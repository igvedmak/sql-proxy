#include <catch2/catch_test_macros.hpp>
#include "config/config_loader.hpp"

#include <cstdlib>

using namespace sqlproxy;

TEST_CASE("EnvConfig: expand env var in connection_string", "[config][env]") {
    ::setenv("TEST_DB_PASSWORD", "s3cret", 1);

    const std::string toml = R"(
[server]
port = 8080

[[databases]]
name = "testdb"
type = "postgresql"
connection_string = "host=localhost password=${TEST_DB_PASSWORD} dbname=test"
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    REQUIRE(result.config.databases.size() == 1);
    CHECK(result.config.databases[0].connection_string ==
          "host=localhost password=s3cret dbname=test");

    ::unsetenv("TEST_DB_PASSWORD");
}

TEST_CASE("EnvConfig: missing env var expands to empty", "[config][env]") {
    ::unsetenv("NONEXISTENT_VAR_XYZ_12345");

    const std::string toml = R"(
[server]
port = 8080

[[databases]]
name = "testdb"
type = "postgresql"
connection_string = "host=localhost password=${NONEXISTENT_VAR_XYZ_12345} dbname=test"
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    CHECK(result.config.databases[0].connection_string ==
          "host=localhost password= dbname=test");
}

TEST_CASE("EnvConfig: unclosed ${ is parse error", "[config][env]") {
    const std::string toml = R"(
[server]
port = 8080

[[databases]]
name = "testdb"
type = "postgresql"
connection_string = "host=localhost password=${UNCLOSED"
)";

    auto result = ConfigLoader::load_from_string(toml);
    CHECK_FALSE(result.success);
    CHECK(result.error_message.find("Unclosed env var") != std::string::npos);
}

TEST_CASE("EnvConfig: multiple env vars in one value", "[config][env]") {
    ::setenv("TEST_HOST", "db.example.com", 1);
    ::setenv("TEST_PORT", "5432", 1);

    const std::string toml = R"(
[server]
port = 8080

[[databases]]
name = "testdb"
type = "postgresql"
connection_string = "host=${TEST_HOST}:${TEST_PORT}/mydb"
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    CHECK(result.config.databases[0].connection_string ==
          "host=db.example.com:5432/mydb");

    ::unsetenv("TEST_HOST");
    ::unsetenv("TEST_PORT");
}

TEST_CASE("EnvConfig: no expansion for non-string values", "[config][env]") {
    // Integers and bools should not go through env expansion
    const std::string toml = R"(
[server]
port = 8080

[[databases]]
name = "testdb"
type = "postgresql"
connection_string = "host=localhost"
min_connections = 5
max_connections = 20
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    CHECK(result.config.databases[0].min_connections == 5);
    CHECK(result.config.databases[0].max_connections == 20);
}
