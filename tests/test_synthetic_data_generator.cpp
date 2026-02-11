#include <catch2/catch_test_macros.hpp>
#include "analyzer/synthetic_data_generator.hpp"

using namespace sqlproxy;

TEST_CASE("SyntheticDataGenerator - disabled", "[synthetic_data]") {
    SyntheticDataGenerator gen;
    REQUIRE_FALSE(gen.is_enabled());
}

TEST_CASE("SyntheticDataGenerator - basic generation", "[synthetic_data]") {
    SyntheticDataGenerator::Config cfg;
    cfg.enabled = true;
    cfg.max_rows = 100;
    SyntheticDataGenerator gen(cfg);

    TableMetadata table;
    table.name = "customers";
    table.columns.emplace_back("id", "integer");
    table.columns.emplace_back("name", "text");
    table.columns.emplace_back("email", "text");

    std::unordered_map<std::string, ClassificationType> classifications;
    classifications["email"] = ClassificationType::PII_EMAIL;

    auto data = gen.generate(table, classifications, 5);

    REQUIRE(data.column_names.size() == 3);
    REQUIRE(data.column_names[0] == "id");
    REQUIRE(data.column_names[1] == "name");
    REQUIRE(data.column_names[2] == "email");

    REQUIRE(data.rows.size() == 5);

    // Check integer generation
    REQUIRE(data.rows[0][0] == "1");
    REQUIRE(data.rows[1][0] == "2");

    // Check text generation
    REQUIRE(data.rows[0][1] == "name_1");

    // Check PII email generation
    REQUIRE(data.rows[0][2] == "user1@example.com");
    REQUIRE(data.rows[1][2] == "user2@example.com");
}

TEST_CASE("SyntheticDataGenerator - PII types", "[synthetic_data]") {
    SyntheticDataGenerator::Config cfg;
    cfg.enabled = true;
    SyntheticDataGenerator gen(cfg);

    TableMetadata table;
    table.columns.emplace_back("phone", "text");
    table.columns.emplace_back("ssn", "text");
    table.columns.emplace_back("cc", "text");
    table.columns.emplace_back("salary", "numeric");

    std::unordered_map<std::string, ClassificationType> cls;
    cls["phone"] = ClassificationType::PII_PHONE;
    cls["ssn"] = ClassificationType::PII_SSN;
    cls["cc"] = ClassificationType::PII_CREDIT_CARD;
    cls["salary"] = ClassificationType::SENSITIVE_SALARY;

    auto data = gen.generate(table, cls, 1);
    REQUIRE(data.rows.size() == 1);

    // Phone: 555-XXXX format
    REQUIRE(data.rows[0][0].find("555-") == 0);

    // SSN: 000-00-XXXX format
    REQUIRE(data.rows[0][1].find("000-00-") == 0);

    // Credit card: 4111... format
    REQUIRE(data.rows[0][2].find("4111") == 0);

    // Salary: numeric value
    int salary = std::stoi(data.rows[0][3]);
    REQUIRE(salary >= 30000);
}

TEST_CASE("SyntheticDataGenerator - max rows limit", "[synthetic_data]") {
    SyntheticDataGenerator::Config cfg;
    cfg.enabled = true;
    cfg.max_rows = 5;
    SyntheticDataGenerator gen(cfg);

    TableMetadata table;
    table.columns.emplace_back("id", "integer");

    auto data = gen.generate(table, {}, 100);
    REQUIRE(data.rows.size() == 5);  // Capped at max_rows
}

TEST_CASE("SyntheticDataGenerator - various column types", "[synthetic_data]") {
    SyntheticDataGenerator::Config cfg;
    cfg.enabled = true;
    SyntheticDataGenerator gen(cfg);

    TableMetadata table;
    table.columns.emplace_back("flag", "boolean");
    table.columns.emplace_back("amount", "numeric");
    table.columns.emplace_back("created", "timestamp");
    table.columns.emplace_back("uid", "uuid");

    auto data = gen.generate(table, {}, 2);
    REQUIRE(data.rows.size() == 2);

    // Boolean alternates
    REQUIRE(data.rows[0][0] == "true");
    REQUIRE(data.rows[1][0] == "false");

    // Numeric has decimal point
    REQUIRE(data.rows[0][1].find('.') != std::string::npos);

    // Timestamp has date format
    REQUIRE(data.rows[0][2].find("2024-") == 0);

    // UUID has dashes
    REQUIRE(data.rows[0][3].find('-') != std::string::npos);
}
