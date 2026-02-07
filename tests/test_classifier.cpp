#include <catch2/catch_test_macros.hpp>
#include "classifier/classifier_registry.hpp"
#include "analyzer/sql_analyzer.hpp"

using namespace sqlproxy;

// Helper to build a QueryResult with given column names and sample rows
static QueryResult make_query_result(
    const std::vector<std::string>& columns,
    const std::vector<std::vector<std::string>>& rows = {},
    const std::vector<uint32_t>& type_oids = {}) {

    QueryResult result;
    result.success = true;
    result.column_names = columns;
    result.rows = rows;
    result.column_type_oids = type_oids;
    return result;
}

// Helper to build a minimal AnalysisResult with no derived columns
static AnalysisResult make_simple_analysis() {
    AnalysisResult analysis;
    analysis.statement_type = StatementType::SELECT;
    return analysis;
}



TEST_CASE("ClassifierRegistry column name classification", "[classifier]") {

    ClassifierRegistry registry;

    SECTION("Email column detected") {
        auto result = make_query_result({"id", "email", "name"});
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.count("email") > 0);
        REQUIRE(cls.classifications.at("email").type == ClassificationType::PII_EMAIL);
    }

    SECTION("Email variants detected") {
        auto result = make_query_result({"email_address", "e_mail", "mail"});
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.count("email_address") > 0);
        REQUIRE(cls.classifications.at("email_address").type == ClassificationType::PII_EMAIL);

        REQUIRE(cls.classifications.count("e_mail") > 0);
        REQUIRE(cls.classifications.at("e_mail").type == ClassificationType::PII_EMAIL);

        REQUIRE(cls.classifications.count("mail") > 0);
        REQUIRE(cls.classifications.at("mail").type == ClassificationType::PII_EMAIL);
    }

    SECTION("Phone column detected") {
        auto result = make_query_result({"phone", "telephone", "mobile"});
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.count("phone") > 0);
        REQUIRE(cls.classifications.at("phone").type == ClassificationType::PII_PHONE);

        REQUIRE(cls.classifications.count("telephone") > 0);
        REQUIRE(cls.classifications.at("telephone").type == ClassificationType::PII_PHONE);

        REQUIRE(cls.classifications.count("mobile") > 0);
        REQUIRE(cls.classifications.at("mobile").type == ClassificationType::PII_PHONE);
    }

    SECTION("SSN column detected") {
        auto result = make_query_result({"ssn"});
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.count("ssn") > 0);
        REQUIRE(cls.classifications.at("ssn").type == ClassificationType::PII_SSN);
    }

    SECTION("Credit card column detected") {
        auto result = make_query_result({"credit_card", "card_number", "cc_number"});
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.count("credit_card") > 0);
        REQUIRE(cls.classifications.at("credit_card").type == ClassificationType::PII_CREDIT_CARD);

        REQUIRE(cls.classifications.count("card_number") > 0);
        REQUIRE(cls.classifications.at("card_number").type == ClassificationType::PII_CREDIT_CARD);
    }

    SECTION("Salary column detected as sensitive") {
        auto result = make_query_result({"salary", "compensation"});
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.count("salary") > 0);
        REQUIRE(cls.classifications.at("salary").type == ClassificationType::SENSITIVE_SALARY);
    }

    SECTION("Password column detected as sensitive") {
        auto result = make_query_result({"password", "pwd"});
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.count("password") > 0);
        REQUIRE(cls.classifications.at("password").type == ClassificationType::SENSITIVE_PASSWORD);
    }

    SECTION("Non-PII columns not classified") {
        auto result = make_query_result({"id", "name", "created_at", "status"});
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        // These generic names should not trigger classification
        REQUIRE(cls.classifications.count("id") == 0);
        REQUIRE(cls.classifications.count("name") == 0);
        REQUIRE(cls.classifications.count("created_at") == 0);
        REQUIRE(cls.classifications.count("status") == 0);
    }

    SECTION("Substring matching detects PII in compound names") {
        auto result = make_query_result({"customer_email", "user_phone_number"});
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        // Substring matching should detect "email" within "customer_email"
        REQUIRE(cls.classifications.count("customer_email") > 0);
        REQUIRE(cls.classifications.at("customer_email").type == ClassificationType::PII_EMAIL);
    }

    SECTION("Case insensitive name matching") {
        auto result = make_query_result({"Email", "PHONE", "Ssn"});
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.count("Email") > 0);
        REQUIRE(cls.classifications.at("Email").type == ClassificationType::PII_EMAIL);

        REQUIRE(cls.classifications.count("PHONE") > 0);
        REQUIRE(cls.classifications.at("PHONE").type == ClassificationType::PII_PHONE);

        REQUIRE(cls.classifications.count("Ssn") > 0);
        REQUIRE(cls.classifications.at("Ssn").type == ClassificationType::PII_SSN);
    }
}

TEST_CASE("ClassifierRegistry regex pattern matching", "[classifier]") {

    ClassifierRegistry registry;

    SECTION("Email pattern detection in values") {
        auto result = make_query_result(
            {"contact_info"},
            {
                {{"alice@example.com"}},
                {{"bob@test.org"}},
                {{"charlie@domain.net"}}
            });
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.count("contact_info") > 0);
        REQUIRE(cls.classifications.at("contact_info").type == ClassificationType::PII_EMAIL);
    }

    SECTION("Phone pattern detection in values") {
        auto result = make_query_result(
            {"contact_number"},
            {
                {{"(555) 123-4567"}},
                {{"555-987-6543"}},
                {{"(555) 111-2222"}}
            });
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.count("contact_number") > 0);
        REQUIRE(cls.classifications.at("contact_number").type == ClassificationType::PII_PHONE);
    }

    SECTION("Below threshold - not classified") {
        // Only 1 out of 3 values match email pattern (below 50% threshold)
        auto result = make_query_result(
            {"data_field"},
            {
                {{"alice@example.com"}},
                {{"not an email"}},
                {{"also not an email"}}
            });
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        // Should not be classified as email since < 50% match
        REQUIRE(cls.classifications.count("data_field") == 0);
    }

    SECTION("Empty result set - no classification") {
        auto result = make_query_result({"some_field"}, {});
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.count("some_field") == 0);
    }
}

TEST_CASE("ClassifierRegistry Luhn validation for credit cards", "[classifier]") {

    ClassifierRegistry registry;

    SECTION("Valid credit card numbers classified") {
        // Valid Luhn numbers (Visa test numbers)
        auto result = make_query_result(
            {"card_data"},
            {
                {{"4111111111111111"}},  // Visa test number (passes Luhn)
                {{"4111111111111111"}},
                {{"4111111111111111"}}
            });
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.count("card_data") > 0);
        REQUIRE(cls.classifications.at("card_data").type == ClassificationType::PII_CREDIT_CARD);
    }

    SECTION("Invalid Luhn numbers not classified as credit cards") {
        // Numbers that look like credit cards but fail Luhn check
        auto result = make_query_result(
            {"some_number"},
            {
                {{"1234567890123456"}},  // Fails Luhn
                {{"1234567890123456"}},
                {{"1234567890123456"}}
            });
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        // Should not be classified as credit card since Luhn fails
        REQUIRE(cls.classifications.count("some_number") == 0);
    }
}

TEST_CASE("ClassifierRegistry SSN validation", "[classifier]") {

    ClassifierRegistry registry;

    SECTION("Valid SSN format classified") {
        auto result = make_query_result(
            {"tax_id"},
            {
                {{"123-45-6789"}},
                {{"234-56-7890"}},
                {{"345-67-8901"}}
            });
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.count("tax_id") > 0);
        REQUIRE(cls.classifications.at("tax_id").type == ClassificationType::PII_SSN);
    }

    SECTION("Invalid SSN area number 000 not classified") {
        auto result = make_query_result(
            {"some_id"},
            {
                {{"000-12-3456"}},
                {{"000-34-5678"}},
                {{"000-56-7890"}}
            });
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        // Area 000 is invalid - should not classify as SSN
        REQUIRE(cls.classifications.count("some_id") == 0);
    }

    SECTION("Invalid SSN area number 666 not classified") {
        auto result = make_query_result(
            {"some_id"},
            {
                {{"666-12-3456"}},
                {{"666-34-5678"}},
                {{"666-56-7890"}}
            });
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.count("some_id") == 0);
    }

    SECTION("Invalid SSN area number 900+ not classified") {
        auto result = make_query_result(
            {"some_id"},
            {
                {{"900-12-3456"}},
                {{"950-34-5678"}},
                {{"999-56-7890"}}
            });
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.count("some_id") == 0);
    }

    SECTION("Invalid SSN group number 00 not classified") {
        auto result = make_query_result(
            {"some_id"},
            {
                {{"123-00-6789"}},
                {{"234-00-7890"}},
                {{"345-00-8901"}}
            });
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.count("some_id") == 0);
    }

    SECTION("Invalid SSN serial number 0000 not classified") {
        auto result = make_query_result(
            {"some_id"},
            {
                {{"123-45-0000"}},
                {{"234-56-0000"}},
                {{"345-67-0000"}}
            });
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.count("some_id") == 0);
    }
}

TEST_CASE("ClassifierRegistry derived column classification", "[classifier]") {

    ClassifierRegistry registry;

    SECTION("PII preserved through UPPER - derived column inherits classification") {
        // Step 1: Classify base columns (email is detected by name)
        auto result = make_query_result({"email", "upper_email"});

        // Step 2: Analysis with derived column tracking
        AnalysisResult analysis;
        analysis.statement_type = StatementType::SELECT;

        // upper_email is derived from email via UPPER()
        ProjectionColumn proj;
        proj.name = "upper_email";
        proj.derived_from = {"email"};
        proj.expression = "upper(email)";
        analysis.projections.push_back(proj);

        auto cls = registry.classify(result, analysis);

        // email detected by name strategy
        REQUIRE(cls.classifications.count("email") > 0);
        REQUIRE(cls.classifications.at("email").type == ClassificationType::PII_EMAIL);

        // upper_email should inherit PII classification
        REQUIRE(cls.classifications.count("upper_email") > 0);
        REQUIRE(cls.classifications.at("upper_email").type == ClassificationType::PII_EMAIL);
        REQUIRE(cls.classifications.at("upper_email").strategy == "DerivedColumn");
    }

    SECTION("PII destroyed by COUNT - derived column not classified") {
        auto result = make_query_result({"email", "email_count"});

        AnalysisResult analysis;
        analysis.statement_type = StatementType::SELECT;

        // email_count derived from email via COUNT()
        ProjectionColumn proj;
        proj.name = "email_count";
        proj.derived_from = {"email"};
        proj.expression = "count(email)";
        analysis.projections.push_back(proj);

        auto cls = registry.classify(result, analysis);

        // email detected
        REQUIRE(cls.classifications.count("email") > 0);

        // email_count should NOT be classified (COUNT destroys PII)
        REQUIRE(cls.classifications.count("email_count") == 0);
    }

    SECTION("PII destroyed by aggregation functions") {
        auto result = make_query_result({"salary", "avg_salary"});

        AnalysisResult analysis;
        analysis.statement_type = StatementType::SELECT;

        ProjectionColumn proj;
        proj.name = "avg_salary";
        proj.derived_from = {"salary"};
        proj.expression = "avg(salary)";
        analysis.projections.push_back(proj);

        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.count("salary") > 0);
        REQUIRE(cls.classifications.at("salary").type == ClassificationType::SENSITIVE_SALARY);

        // avg_salary should NOT be classified (AVG destroys individual PII)
        REQUIRE(cls.classifications.count("avg_salary") == 0);
    }

    SECTION("PII preserved through LOWER, TRIM, SUBSTRING") {
        auto result = make_query_result({"phone", "trimmed_phone"});

        AnalysisResult analysis;
        analysis.statement_type = StatementType::SELECT;

        ProjectionColumn proj;
        proj.name = "trimmed_phone";
        proj.derived_from = {"phone"};
        proj.expression = "trim(phone)";
        analysis.projections.push_back(proj);

        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.count("phone") > 0);
        REQUIRE(cls.classifications.at("phone").type == ClassificationType::PII_PHONE);

        // TRIM preserves PII
        REQUIRE(cls.classifications.count("trimmed_phone") > 0);
        REQUIRE(cls.classifications.at("trimmed_phone").type == ClassificationType::PII_PHONE);
    }

    SECTION("PII destroyed by MD5 hash") {
        auto result = make_query_result({"email", "hashed_email"});

        AnalysisResult analysis;
        analysis.statement_type = StatementType::SELECT;

        ProjectionColumn proj;
        proj.name = "hashed_email";
        proj.derived_from = {"email"};
        proj.expression = "md5(email)";
        analysis.projections.push_back(proj);

        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.count("email") > 0);
        // MD5 destroys PII
        REQUIRE(cls.classifications.count("hashed_email") == 0);
    }

    SECTION("PII destroyed by LENGTH") {
        auto result = make_query_result({"ssn", "ssn_length"});

        AnalysisResult analysis;
        analysis.statement_type = StatementType::SELECT;

        ProjectionColumn proj;
        proj.name = "ssn_length";
        proj.derived_from = {"ssn"};
        proj.expression = "length(ssn)";
        analysis.projections.push_back(proj);

        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.count("ssn") > 0);
        // LENGTH destroys PII
        REQUIRE(cls.classifications.count("ssn_length") == 0);
    }
}

TEST_CASE("ClassifierRegistry empty and failed results", "[classifier]") {

    ClassifierRegistry registry;

    SECTION("Failed query result returns empty classification") {
        QueryResult result;
        result.success = false;
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.empty());
    }

    SECTION("Result with no columns returns empty classification") {
        QueryResult result;
        result.success = true;
        // No column_names
        auto analysis = make_simple_analysis();
        auto cls = registry.classify(result, analysis);

        REQUIRE(cls.classifications.empty());
    }
}

TEST_CASE("ColumnClassification type_string", "[classifier]") {

    SECTION("PII_EMAIL type string") {
        ColumnClassification cls;
        cls.type = ClassificationType::PII_EMAIL;
        REQUIRE(cls.type_string() == "PII.Email");
    }

    SECTION("PII_PHONE type string") {
        ColumnClassification cls;
        cls.type = ClassificationType::PII_PHONE;
        REQUIRE(cls.type_string() == "PII.Phone");
    }

    SECTION("PII_SSN type string") {
        ColumnClassification cls;
        cls.type = ClassificationType::PII_SSN;
        REQUIRE(cls.type_string() == "PII.SSN");
    }

    SECTION("PII_CREDIT_CARD type string") {
        ColumnClassification cls;
        cls.type = ClassificationType::PII_CREDIT_CARD;
        REQUIRE(cls.type_string() == "PII.CreditCard");
    }

    SECTION("SENSITIVE_SALARY type string") {
        ColumnClassification cls;
        cls.type = ClassificationType::SENSITIVE_SALARY;
        REQUIRE(cls.type_string() == "Sensitive.Salary");
    }

    SECTION("SENSITIVE_PASSWORD type string") {
        ColumnClassification cls;
        cls.type = ClassificationType::SENSITIVE_PASSWORD;
        REQUIRE(cls.type_string() == "Sensitive.Password");
    }

    SECTION("CUSTOM type string uses custom_label") {
        ColumnClassification cls;
        cls.type = ClassificationType::CUSTOM;
        cls.custom_label = "HIPAA.MedicalRecord";
        REQUIRE(cls.type_string() == "HIPAA.MedicalRecord");
    }

    SECTION("NONE type string") {
        ColumnClassification cls;
        cls.type = ClassificationType::NONE;
        REQUIRE(cls.type_string() == "None");
    }
}
