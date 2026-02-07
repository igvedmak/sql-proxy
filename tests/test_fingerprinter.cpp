#include <catch2/catch_test_macros.hpp>
#include "parser/fingerprinter.hpp"

using namespace sqlproxy;

TEST_CASE("QueryFingerprinter normalization", "[fingerprinter]") {

    SECTION("Basic whitespace normalization") {
        auto fp = QueryFingerprinter::fingerprint(
            "SELECT  *   FROM   users   WHERE   id  =  ?");
        // Multiple spaces should collapse to single spaces
        REQUIRE(fp.normalized.find("  ") == std::string::npos);
    }

    SECTION("Leading and trailing whitespace is removed") {
        auto fp = QueryFingerprinter::fingerprint("   SELECT * FROM users   ");
        REQUIRE(fp.normalized.front() != ' ');
        REQUIRE(fp.normalized.back() != ' ');
    }

    SECTION("Tab and newline normalization") {
        auto fp = QueryFingerprinter::fingerprint(
            "SELECT *\n\tFROM\tusers\n\tWHERE id = 1");
        REQUIRE(fp.normalized.find('\n') == std::string::npos);
        REQUIRE(fp.normalized.find('\t') == std::string::npos);
    }

    SECTION("Case normalization - keywords lowercased") {
        auto fp = QueryFingerprinter::fingerprint("SELECT * FROM Users WHERE Id = 1");
        // Keywords and identifiers are lowercased
        REQUIRE(fp.normalized.find("select") != std::string::npos);
        REQUIRE(fp.normalized.find("from") != std::string::npos);
        REQUIRE(fp.normalized.find("where") != std::string::npos);
        // Should not contain uppercase versions
        REQUIRE(fp.normalized.find("SELECT") == std::string::npos);
        REQUIRE(fp.normalized.find("FROM") == std::string::npos);
    }
}

TEST_CASE("QueryFingerprinter string literal parameterization", "[fingerprinter]") {

    SECTION("Single-quoted string replaced with ?") {
        auto fp = QueryFingerprinter::fingerprint(
            "SELECT * FROM users WHERE name = 'John'");
        REQUIRE(fp.normalized.find("'John'") == std::string::npos);
        REQUIRE(fp.normalized.find("?") != std::string::npos);
    }

    SECTION("Multiple string literals replaced") {
        auto fp = QueryFingerprinter::fingerprint(
            "SELECT * FROM users WHERE name = 'John' AND city = 'NYC'");
        REQUIRE(fp.normalized.find("'John'") == std::string::npos);
        REQUIRE(fp.normalized.find("'NYC'") == std::string::npos);
        // Should have ? placeholders
        size_t first_q = fp.normalized.find('?');
        REQUIRE(first_q != std::string::npos);
        size_t second_q = fp.normalized.find('?', first_q + 1);
        REQUIRE(second_q != std::string::npos);
    }

    SECTION("Escaped quotes within string literals") {
        auto fp = QueryFingerprinter::fingerprint(
            "SELECT * FROM users WHERE name = 'O''Brien'");
        REQUIRE(fp.normalized.find("O''Brien") == std::string::npos);
        REQUIRE(fp.normalized.find("?") != std::string::npos);
    }

    SECTION("Empty string literal replaced") {
        auto fp = QueryFingerprinter::fingerprint(
            "SELECT * FROM users WHERE name = ''");
        REQUIRE(fp.normalized.find("''") == std::string::npos);
        REQUIRE(fp.normalized.find("?") != std::string::npos);
    }
}

TEST_CASE("QueryFingerprinter number literal parameterization", "[fingerprinter]") {

    SECTION("Integer replaced with ?") {
        auto fp = QueryFingerprinter::fingerprint(
            "SELECT * FROM users WHERE id = 42");
        REQUIRE(fp.normalized.find("42") == std::string::npos);
        REQUIRE(fp.normalized.find("?") != std::string::npos);
    }

    SECTION("Floating point number replaced with ?") {
        auto fp = QueryFingerprinter::fingerprint(
            "SELECT * FROM products WHERE price > 19.99");
        REQUIRE(fp.normalized.find("19.99") == std::string::npos);
        REQUIRE(fp.normalized.find("?") != std::string::npos);
    }

    SECTION("Multiple numbers replaced") {
        auto fp = QueryFingerprinter::fingerprint(
            "SELECT * FROM users WHERE id = 1 AND age > 25");
        REQUIRE(fp.normalized.find(" 1 ") == std::string::npos);
        REQUIRE(fp.normalized.find("25") == std::string::npos);
    }
}

TEST_CASE("QueryFingerprinter IN-list collapsing", "[fingerprinter]") {

    SECTION("IN list with integers collapsed") {
        auto fp = QueryFingerprinter::fingerprint(
            "SELECT * FROM users WHERE id IN (1, 2, 3)");
        // IN-list should be collapsed to IN (?)
        REQUIRE(fp.normalized.find("(?)") != std::string::npos);
        // Individual numbers should not appear
        REQUIRE(fp.normalized.find(", 2") == std::string::npos);
    }

    SECTION("IN list with strings collapsed") {
        auto fp = QueryFingerprinter::fingerprint(
            "SELECT * FROM users WHERE status IN ('active', 'pending', 'inactive')");
        REQUIRE(fp.normalized.find("(?)") != std::string::npos);
        REQUIRE(fp.normalized.find("'active'") == std::string::npos);
    }

    SECTION("IN list with many elements collapsed to single placeholder") {
        auto fp = QueryFingerprinter::fingerprint(
            "SELECT * FROM t WHERE x IN (1,2,3,4,5,6,7,8,9,10)");
        REQUIRE(fp.normalized.find("(?)") != std::string::npos);
    }
}

TEST_CASE("QueryFingerprinter comment stripping", "[fingerprinter]") {

    SECTION("Block comments removed") {
        auto fp = QueryFingerprinter::fingerprint(
            "SELECT /* this is a comment */ * FROM users");
        REQUIRE(fp.normalized.find("this is a comment") == std::string::npos);
        REQUIRE(fp.normalized.find("/*") == std::string::npos);
        REQUIRE(fp.normalized.find("*/") == std::string::npos);
        REQUIRE(fp.normalized.find("select") != std::string::npos);
        REQUIRE(fp.normalized.find("users") != std::string::npos);
    }

    SECTION("Line comments removed") {
        auto fp = QueryFingerprinter::fingerprint(
            "SELECT * FROM users -- this is a line comment\nWHERE id = 1");
        REQUIRE(fp.normalized.find("this is a line comment") == std::string::npos);
        REQUIRE(fp.normalized.find("--") == std::string::npos);
        REQUIRE(fp.normalized.find("select") != std::string::npos);
        REQUIRE(fp.normalized.find("where") != std::string::npos);
    }

    SECTION("Multiple block comments removed") {
        auto fp = QueryFingerprinter::fingerprint(
            "/* comment1 */ SELECT * /* comment2 */ FROM users /* comment3 */");
        REQUIRE(fp.normalized.find("comment") == std::string::npos);
        REQUIRE(fp.normalized.find("select") != std::string::npos);
        REQUIRE(fp.normalized.find("users") != std::string::npos);
    }
}

TEST_CASE("QueryFingerprinter hash consistency", "[fingerprinter]") {

    SECTION("Same query produces same hash") {
        auto fp1 = QueryFingerprinter::fingerprint("SELECT * FROM users WHERE id = 1");
        auto fp2 = QueryFingerprinter::fingerprint("SELECT * FROM users WHERE id = 1");
        REQUIRE(fp1.hash == fp2.hash);
        REQUIRE(fp1.normalized == fp2.normalized);
    }

    SECTION("Same query with different literals produces same hash") {
        auto fp1 = QueryFingerprinter::fingerprint(
            "SELECT * FROM users WHERE id = 1 AND name = 'Alice'");
        auto fp2 = QueryFingerprinter::fingerprint(
            "SELECT * FROM users WHERE id = 999 AND name = 'Bob'");
        REQUIRE(fp1.hash == fp2.hash);
        REQUIRE(fp1.normalized == fp2.normalized);
    }

    SECTION("Same query with different whitespace produces same hash") {
        auto fp1 = QueryFingerprinter::fingerprint("SELECT * FROM users");
        auto fp2 = QueryFingerprinter::fingerprint("SELECT  *  FROM  users");
        REQUIRE(fp1.hash == fp2.hash);
    }

    SECTION("Same query with different case produces same hash") {
        auto fp1 = QueryFingerprinter::fingerprint("SELECT * FROM users");
        auto fp2 = QueryFingerprinter::fingerprint("select * from users");
        REQUIRE(fp1.hash == fp2.hash);
    }

    SECTION("Different queries produce different hashes") {
        auto fp1 = QueryFingerprinter::fingerprint("SELECT * FROM users");
        auto fp2 = QueryFingerprinter::fingerprint("SELECT * FROM orders");
        REQUIRE(fp1.hash != fp2.hash);
        REQUIRE(fp1.normalized != fp2.normalized);
    }

    SECTION("Same query with different IN-list sizes produces same hash") {
        auto fp1 = QueryFingerprinter::fingerprint(
            "SELECT * FROM users WHERE id IN (1, 2, 3)");
        auto fp2 = QueryFingerprinter::fingerprint(
            "SELECT * FROM users WHERE id IN (10, 20, 30, 40, 50)");
        REQUIRE(fp1.hash == fp2.hash);
        REQUIRE(fp1.normalized == fp2.normalized);
    }

    SECTION("Hash is non-zero for valid queries") {
        auto fp = QueryFingerprinter::fingerprint("SELECT 1");
        REQUIRE(fp.hash != 0);
    }
}

TEST_CASE("QueryFingerprinter preserves identifiers", "[fingerprinter]") {

    SECTION("Table and column names preserved in lowercase") {
        auto fp = QueryFingerprinter::fingerprint(
            "SELECT name, email FROM customers WHERE active = 1");
        REQUIRE(fp.normalized.find("name") != std::string::npos);
        REQUIRE(fp.normalized.find("email") != std::string::npos);
        REQUIRE(fp.normalized.find("customers") != std::string::npos);
        REQUIRE(fp.normalized.find("active") != std::string::npos);
    }

    SECTION("Quoted identifiers preserved") {
        auto fp = QueryFingerprinter::fingerprint(
            "SELECT \"Name\" FROM \"Users\"");
        // Double-quoted identifiers should be preserved (lowercased within quotes)
        REQUIRE(fp.normalized.find("\"") != std::string::npos);
    }
}
