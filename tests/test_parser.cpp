#include <catch2/catch_test_macros.hpp>
#include "parser/sql_parser.hpp"
#include "parser/parse_cache.hpp"

using namespace sqlproxy;

TEST_CASE("SQLParser statement type detection", "[parser]") {

    SQLParser parser;

    SECTION("SELECT statement") {
        auto result = parser.parse("SELECT * FROM users");
        REQUIRE(result.success);
        REQUIRE(result.statement_info->parsed.type == StatementType::SELECT);
        REQUIRE_FALSE(result.statement_info->parsed.is_write);
        REQUIRE_FALSE(result.statement_info->parsed.is_transaction);
    }

    SECTION("INSERT statement") {
        auto result = parser.parse("INSERT INTO users (name) VALUES ('test')");
        REQUIRE(result.success);
        REQUIRE(result.statement_info->parsed.type == StatementType::INSERT);
        REQUIRE(result.statement_info->parsed.is_write);
    }

    SECTION("UPDATE statement") {
        auto result = parser.parse("UPDATE users SET name = 'test' WHERE id = 1");
        REQUIRE(result.success);
        REQUIRE(result.statement_info->parsed.type == StatementType::UPDATE);
        REQUIRE(result.statement_info->parsed.is_write);
    }

    SECTION("DELETE statement") {
        auto result = parser.parse("DELETE FROM users WHERE id = 1");
        REQUIRE(result.success);
        REQUIRE(result.statement_info->parsed.type == StatementType::DELETE);
        REQUIRE(result.statement_info->parsed.is_write);
    }

    SECTION("CREATE TABLE statement") {
        auto result = parser.parse(
            "CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT)");
        REQUIRE(result.success);
        REQUIRE(result.statement_info->parsed.type == StatementType::CREATE_TABLE);
        REQUIRE(result.statement_info->parsed.is_write);
    }

    SECTION("DROP TABLE statement") {
        auto result = parser.parse("DROP TABLE test_table");
        REQUIRE(result.success);
        REQUIRE(result.statement_info->parsed.type == StatementType::DROP_TABLE);
        REQUIRE(result.statement_info->parsed.is_write);
    }

    SECTION("BEGIN transaction") {
        auto result = parser.parse("BEGIN");
        REQUIRE(result.success);
        REQUIRE(result.statement_info->parsed.type == StatementType::BEGIN);
        REQUIRE(result.statement_info->parsed.is_transaction);
        REQUIRE_FALSE(result.statement_info->parsed.is_write);
    }

    SECTION("COMMIT transaction") {
        auto result = parser.parse("COMMIT");
        REQUIRE(result.success);
        REQUIRE(result.statement_info->parsed.type == StatementType::COMMIT);
        REQUIRE(result.statement_info->parsed.is_transaction);
    }

    SECTION("ROLLBACK transaction") {
        auto result = parser.parse("ROLLBACK");
        REQUIRE(result.success);
        REQUIRE(result.statement_info->parsed.type == StatementType::ROLLBACK);
        REQUIRE(result.statement_info->parsed.is_transaction);
    }

    SECTION("TRUNCATE statement") {
        auto result = parser.parse("TRUNCATE users");
        REQUIRE(result.success);
        REQUIRE(result.statement_info->parsed.type == StatementType::TRUNCATE);
        REQUIRE(result.statement_info->parsed.is_write);
    }

    SECTION("SET statement") {
        auto result = parser.parse("SET search_path TO public");
        REQUIRE(result.success);
        REQUIRE(result.statement_info->parsed.type == StatementType::SET);
        REQUIRE_FALSE(result.statement_info->parsed.is_write);
        REQUIRE_FALSE(result.statement_info->parsed.is_transaction);
    }
}

TEST_CASE("SQLParser table extraction", "[parser]") {

    SQLParser parser;

    SECTION("Simple SELECT - single table") {
        auto result = parser.parse("SELECT * FROM users");
        REQUIRE(result.success);
        REQUIRE(result.statement_info->parsed.tables.size() >= 1);

        bool found_users = false;
        for (const auto& table : result.statement_info->parsed.tables) {
            if (table.table == "users") {
                found_users = true;
                break;
            }
        }
        REQUIRE(found_users);
    }

    SECTION("JOIN - multiple tables") {
        auto result = parser.parse(
            "SELECT o.id FROM orders o "
            "JOIN customers c ON o.customer_id = c.id");
        REQUIRE(result.success);
        REQUIRE(result.statement_info->parsed.tables.size() >= 2);

        bool found_orders = false;
        bool found_customers = false;
        for (const auto& table : result.statement_info->parsed.tables) {
            if (table.table == "orders") found_orders = true;
            if (table.table == "customers") found_customers = true;
        }
        REQUIRE(found_orders);
        REQUIRE(found_customers);
    }

    SECTION("Subquery - tables from inner and outer") {
        auto result = parser.parse(
            "SELECT * FROM customers WHERE id IN "
            "(SELECT customer_id FROM orders)");
        REQUIRE(result.success);

        bool found_customers = false;
        bool found_orders = false;
        for (const auto& table : result.statement_info->parsed.tables) {
            if (table.table == "customers") found_customers = true;
            if (table.table == "orders") found_orders = true;
        }
        REQUIRE(found_customers);
        REQUIRE(found_orders);
    }

    SECTION("Schema-qualified table name") {
        auto result = parser.parse("SELECT * FROM public.users");
        REQUIRE(result.success);

        bool found = false;
        for (const auto& table : result.statement_info->parsed.tables) {
            if (table.table == "users" && table.schema == "public") {
                found = true;
                break;
            }
        }
        REQUIRE(found);
    }

    SECTION("INSERT INTO - table extraction") {
        auto result = parser.parse("INSERT INTO orders (customer_id) VALUES (1)");
        REQUIRE(result.success);

        bool found_orders = false;
        for (const auto& table : result.statement_info->parsed.tables) {
            if (table.table == "orders") {
                found_orders = true;
                break;
            }
        }
        REQUIRE(found_orders);
    }

    SECTION("UPDATE - table extraction") {
        auto result = parser.parse("UPDATE customers SET name = 'test' WHERE id = 1");
        REQUIRE(result.success);

        bool found_customers = false;
        for (const auto& table : result.statement_info->parsed.tables) {
            if (table.table == "customers") {
                found_customers = true;
                break;
            }
        }
        REQUIRE(found_customers);
    }

    SECTION("DELETE FROM - table extraction") {
        auto result = parser.parse("DELETE FROM order_items WHERE id = 1");
        REQUIRE(result.success);

        bool found = false;
        for (const auto& table : result.statement_info->parsed.tables) {
            if (table.table == "order_items") {
                found = true;
                break;
            }
        }
        REQUIRE(found);
    }
}

TEST_CASE("SQLParser error handling", "[parser]") {

    SQLParser parser;

    SECTION("Empty query returns error") {
        auto result = parser.parse("");
        REQUIRE_FALSE(result.success);
        REQUIRE(result.error_code == SQLParser::ErrorCode::EMPTY_QUERY);
    }

    SECTION("Whitespace-only query returns error") {
        auto result = parser.parse("   \t\n  ");
        REQUIRE_FALSE(result.success);
        REQUIRE(result.error_code == SQLParser::ErrorCode::EMPTY_QUERY);
    }

    SECTION("Syntax error detected") {
        auto result = parser.parse("SELCT * FORM users");
        REQUIRE_FALSE(result.success);
        REQUIRE(result.error_code == SQLParser::ErrorCode::SYNTAX_ERROR);
        REQUIRE_FALSE(result.error_message.empty());
    }

    SECTION("Incomplete SQL returns error") {
        auto result = parser.parse("SELECT * FROM");
        REQUIRE_FALSE(result.success);
    }

    SECTION("Multiple semicolons handled") {
        // Single statement with trailing semicolon
        auto result = parser.parse("SELECT 1;");
        REQUIRE(result.success);
    }
}

TEST_CASE("SQLParser with cache", "[parser]") {

    auto cache = std::make_shared<ParseCache>(1000, 4);
    SQLParser parser(cache);

    SECTION("Cache hit returns same result") {
        auto result1 = parser.parse("SELECT * FROM users WHERE id = 1");
        REQUIRE(result1.success);

        auto result2 = parser.parse("SELECT * FROM users WHERE id = 2");
        REQUIRE(result2.success);

        // Same fingerprint (only literal differs) -> should hit cache
        auto stats = parser.get_cache_stats();
        // After two parses of same fingerprint, there should be at least 1 hit
        REQUIRE(stats.hits >= 1);
    }

    SECTION("Different queries produce different cache entries") {
        parser.parse("SELECT * FROM users");
        parser.parse("SELECT * FROM orders");

        auto stats = parser.get_cache_stats();
        REQUIRE(stats.total_entries >= 2);
    }

    SECTION("Cache clear works") {
        parser.parse("SELECT * FROM users");
        parser.clear_cache();
        auto stats = parser.get_cache_stats();
        REQUIRE(stats.total_entries == 0);
    }
}

TEST_CASE("SQLParser fingerprint populated", "[parser]") {

    SQLParser parser;

    SECTION("Fingerprint hash is set on successful parse") {
        auto result = parser.parse("SELECT * FROM users WHERE id = 42");
        REQUIRE(result.success);
        REQUIRE(result.statement_info->fingerprint.hash != 0);
        REQUIRE_FALSE(result.statement_info->fingerprint.normalized.empty());
    }

    SECTION("Fingerprint normalized form has parameterized literals") {
        auto result = parser.parse("SELECT * FROM users WHERE id = 42");
        REQUIRE(result.success);
        REQUIRE(result.statement_info->fingerprint.normalized.find("42") == std::string::npos);
        REQUIRE(result.statement_info->fingerprint.normalized.find("?") != std::string::npos);
    }
}
