#include <catch2/catch_test_macros.hpp>
#include "config/config_loader.hpp"
#include <filesystem>
#include <fstream>

using namespace sqlproxy;

namespace {

// RAII temporary directory
struct TmpDir {
    std::filesystem::path path;
    TmpDir() : path(std::filesystem::temp_directory_path() / "sqlproxy_test_include") {
        std::filesystem::create_directories(path);
    }
    ~TmpDir() { std::filesystem::remove_all(path); }
    std::string file(const std::string& name, const std::string& content) {
        auto p = path / name;
        std::ofstream f(p);
        f << content;
        return p.string();
    }
};

} // namespace

TEST_CASE("ConfigInclude: single include file loads and merges", "[config][include]") {
    TmpDir tmp;

    tmp.file("users.toml", R"(
[[users]]
name = "included_user"
roles = ["reader"]
)");

    auto main_path = tmp.file("main.toml", R"(
include = "users.toml"

[server]
host = "0.0.0.0"
port = 8080

[[databases]]
name = "testdb"
type = "postgresql"
connection_string = "host=localhost dbname=testdb"
)");

    auto result = ConfigLoader::load_from_file(main_path);
    REQUIRE(result.success);
    CHECK(result.config.users.count("included_user") == 1);
}

TEST_CASE("ConfigInclude: array includes concatenate policies", "[config][include]") {
    TmpDir tmp;

    tmp.file("policies_a.toml", R"(
[[policies]]
name = "policy_a"
database = "testdb"
action = "allow"
)");

    tmp.file("policies_b.toml", R"(
[[policies]]
name = "policy_b"
database = "testdb"
action = "mask"
)");

    auto main_path = tmp.file("main.toml", R"(
include = ["policies_a.toml", "policies_b.toml"]

[server]
host = "0.0.0.0"
port = 8080

[[databases]]
name = "testdb"
type = "postgresql"
connection_string = "host=localhost dbname=testdb"

[[policies]]
name = "main_policy"
database = "testdb"
action = "allow"
)");

    auto result = ConfigLoader::load_from_file(main_path);
    REQUIRE(result.success);
    // Should have main + both included policies
    CHECK(result.config.policies.size() >= 3);
}

TEST_CASE("ConfigInclude: main config scalars override included", "[config][include]") {
    TmpDir tmp;

    tmp.file("base.toml", R"(
[server]
host = "127.0.0.1"
port = 9999
)");

    auto main_path = tmp.file("main.toml", R"(
include = "base.toml"

[server]
host = "0.0.0.0"
port = 8080

[[databases]]
name = "testdb"
type = "postgresql"
connection_string = "host=localhost dbname=testdb"
)");

    auto result = ConfigLoader::load_from_file(main_path);
    REQUIRE(result.success);
    // Main config wins
    CHECK(result.config.server.host == "0.0.0.0");
    CHECK(result.config.server.port == 8080);
}

TEST_CASE("ConfigInclude: circular include detection throws", "[config][include]") {
    TmpDir tmp;

    // a.toml includes b.toml, b.toml includes a.toml
    auto a_path = (tmp.path / "a.toml").string();
    auto b_path = (tmp.path / "b.toml").string();

    {
        std::ofstream f(a_path);
        f << "include = \"b.toml\"\n[server]\nhost = \"0.0.0.0\"\nport = 8080\n";
    }
    {
        std::ofstream f(b_path);
        f << "include = \"a.toml\"\n";
    }

    auto result = ConfigLoader::load_from_file(a_path);
    CHECK_FALSE(result.success);
    CHECK(result.error_message.find("ircular") != std::string::npos);
}

TEST_CASE("ConfigInclude: missing include file throws with path", "[config][include]") {
    TmpDir tmp;

    auto main_path = tmp.file("main.toml", R"(
include = "nonexistent.toml"

[server]
host = "0.0.0.0"
port = 8080
)");

    auto result = ConfigLoader::load_from_file(main_path);
    CHECK_FALSE(result.success);
    CHECK(result.error_message.find("nonexistent.toml") != std::string::npos);
}
