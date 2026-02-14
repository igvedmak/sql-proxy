#include <catch2/catch_test_macros.hpp>
#include "catalog/data_catalog.hpp"
#include "analyzer/sql_analyzer.hpp"
#include "policy/policy_types.hpp"

using namespace sqlproxy;

static DataCatalog::Config default_config() {
    DataCatalog::Config cfg;
    cfg.enabled = true;
    cfg.max_tables = 1000;
    cfg.max_columns_per_table = 100;
    return cfg;
}

static AnalysisResult make_analysis(const std::string& table,
                                     const std::string& schema = "public") {
    AnalysisResult a;
    a.statement_type = StatementType::SELECT;
    a.source_tables.push_back(TableRef{schema, table});
    return a;
}

static ClassificationResult make_classification(
    const std::string& col, ClassificationType type,
    double conf = 0.9, const std::string& strategy = "pattern") {
    ClassificationResult cr;
    cr.classifications[col] = ColumnClassification(col, type, conf, strategy);
    return cr;
}

TEST_CASE("DataCatalog", "[catalog]") {

    SECTION("Default-constructed catalog is enabled") {
        DataCatalog catalog;
        auto stats = catalog.get_stats();
        REQUIRE(stats.total_tables == 0);
        REQUIRE(stats.total_columns == 0);
    }

    SECTION("Disabled catalog ignores records") {
        DataCatalog::Config cfg;
        cfg.enabled = false;
        DataCatalog catalog(cfg);

        auto analysis = make_analysis("customers");
        auto cls = make_classification("email", ClassificationType::PII_EMAIL);

        catalog.record_classifications("testdb", "alice", analysis, cls, {});
        auto stats = catalog.get_stats();
        REQUIRE(stats.total_tables == 0);
        REQUIRE(stats.total_columns == 0);
    }

    SECTION("Record classification creates table and column") {
        DataCatalog catalog(default_config());

        auto analysis = make_analysis("customers");
        auto cls = make_classification("email", ClassificationType::PII_EMAIL);

        catalog.record_classifications("testdb", "alice", analysis, cls, {});

        auto stats = catalog.get_stats();
        REQUIRE(stats.total_tables == 1);
        REQUIRE(stats.total_columns == 1);
        REQUIRE(stats.pii_columns == 1);
        REQUIRE(stats.total_classifications_recorded == 1);
    }

    SECTION("Get tables returns recorded tables") {
        DataCatalog catalog(default_config());

        auto a1 = make_analysis("customers");
        auto c1 = make_classification("email", ClassificationType::PII_EMAIL);
        catalog.record_classifications("testdb", "alice", a1, c1, {});

        auto a2 = make_analysis("orders");
        auto c2 = make_classification("total", ClassificationType::NONE);
        catalog.record_classifications("testdb", "bob", a2, c2, {});

        auto tables = catalog.get_tables();
        REQUIRE(tables.size() == 2);
    }

    SECTION("Get columns for specific table") {
        DataCatalog catalog(default_config());

        auto analysis = make_analysis("customers");
        ClassificationResult cls;
        cls.classifications["email"] = ColumnClassification(
            "email", ClassificationType::PII_EMAIL, 0.95, "pattern");
        cls.classifications["phone"] = ColumnClassification(
            "phone", ClassificationType::PII_PHONE, 0.85, "pattern");

        catalog.record_classifications("testdb", "alice", analysis, cls, {});

        auto cols = catalog.get_columns("public.customers");
        REQUIRE(cols.size() == 2);

        // Verify column details
        bool found_email = false, found_phone = false;
        for (const auto& col : cols) {
            if (col.column == "email") {
                found_email = true;
                REQUIRE(col.pii_type == ClassificationType::PII_EMAIL);
                REQUIRE(col.confidence == 0.95);
                REQUIRE(col.access_count == 1);
            } else if (col.column == "phone") {
                found_phone = true;
                REQUIRE(col.pii_type == ClassificationType::PII_PHONE);
                REQUIRE(col.confidence == 0.85);
            }
        }
        REQUIRE(found_email);
        REQUIRE(found_phone);
    }

    SECTION("Multiple accesses increment counters") {
        DataCatalog catalog(default_config());

        auto analysis = make_analysis("customers");
        auto cls = make_classification("email", ClassificationType::PII_EMAIL);

        catalog.record_classifications("testdb", "alice", analysis, cls, {});
        catalog.record_classifications("testdb", "bob", analysis, cls, {});
        catalog.record_classifications("testdb", "alice", analysis, cls, {});

        auto cols = catalog.get_columns("public.customers");
        REQUIRE(cols.size() == 1);
        REQUIRE(cols[0].access_count == 3);
        REQUIRE(cols[0].accessing_users.size() == 2);

        auto tables = catalog.get_tables();
        REQUIRE(tables.size() == 1);
        REQUIRE(tables[0].total_accesses == 3);
    }

    SECTION("Masked columns are tracked") {
        DataCatalog catalog(default_config());

        auto analysis = make_analysis("customers");
        auto cls = make_classification("email", ClassificationType::PII_EMAIL);
        std::vector<MaskingRecord> masking;
        masking.push_back({"email", MaskingAction::REDACT, "pii-policy"});

        catalog.record_classifications("testdb", "alice", analysis, cls, masking);

        auto cols = catalog.get_columns("public.customers");
        REQUIRE(cols.size() == 1);
        REQUIRE(cols[0].masked_count == 1);
    }

    SECTION("Higher confidence replaces lower") {
        DataCatalog catalog(default_config());

        auto analysis = make_analysis("customers");
        auto cls_low = make_classification("email", ClassificationType::PII_EMAIL, 0.6);
        auto cls_high = make_classification("email", ClassificationType::PII_EMAIL, 0.95);

        catalog.record_classifications("testdb", "alice", analysis, cls_low, {});
        catalog.record_classifications("testdb", "alice", analysis, cls_high, {});

        auto cols = catalog.get_columns("public.customers");
        REQUIRE(cols.size() == 1);
        REQUIRE(cols[0].confidence == 0.95);
    }

    SECTION("Search PII returns only PII columns") {
        DataCatalog catalog(default_config());

        auto analysis = make_analysis("customers");
        ClassificationResult cls;
        cls.classifications["email"] = ColumnClassification(
            "email", ClassificationType::PII_EMAIL, 0.9, "pattern");
        cls.classifications["name"] = ColumnClassification(
            "name", ClassificationType::NONE, 0.0, "");

        catalog.record_classifications("testdb", "alice", analysis, cls, {});

        auto pii = catalog.search_pii();
        REQUIRE(pii.size() == 1);
        REQUIRE(pii[0].column == "email");
        REQUIRE(pii[0].pii_type == ClassificationType::PII_EMAIL);
    }

    SECTION("Search PII by specific type") {
        DataCatalog catalog(default_config());

        auto analysis = make_analysis("customers");
        ClassificationResult cls;
        cls.classifications["email"] = ColumnClassification(
            "email", ClassificationType::PII_EMAIL, 0.9, "pattern");
        cls.classifications["phone"] = ColumnClassification(
            "phone", ClassificationType::PII_PHONE, 0.85, "pattern");

        catalog.record_classifications("testdb", "alice", analysis, cls, {});

        auto emails_only = catalog.search_pii(ClassificationType::PII_EMAIL);
        REQUIRE(emails_only.size() == 1);
        REQUIRE(emails_only[0].column == "email");

        auto phones_only = catalog.search_pii(ClassificationType::PII_PHONE);
        REQUIRE(phones_only.size() == 1);
        REQUIRE(phones_only[0].column == "phone");

        auto all_pii = catalog.search_pii();
        REQUIRE(all_pii.size() == 2);
    }

    SECTION("Text search is case-insensitive") {
        DataCatalog catalog(default_config());

        auto analysis = make_analysis("customers");
        auto cls = make_classification("Email_Address", ClassificationType::PII_EMAIL);
        catalog.record_classifications("testdb", "alice", analysis, cls, {});

        auto results = catalog.search("email");
        REQUIRE(results.size() == 1);
        REQUIRE(results[0].column == "Email_Address");

        auto results2 = catalog.search("CUSTOMER");
        REQUIRE(results2.size() == 1);
    }

    SECTION("Text search returns empty for no match") {
        DataCatalog catalog(default_config());

        auto analysis = make_analysis("customers");
        auto cls = make_classification("email", ClassificationType::PII_EMAIL);
        catalog.record_classifications("testdb", "alice", analysis, cls, {});

        auto results = catalog.search("xyz_nonexistent");
        REQUIRE(results.empty());
    }

    SECTION("Text search with empty query returns empty") {
        DataCatalog catalog(default_config());
        auto results = catalog.search("");
        REQUIRE(results.empty());
    }

    SECTION("Seed from schema populates tables and columns") {
        DataCatalog catalog(default_config());

        SchemaMap schema;
        auto meta = std::make_shared<TableMetadata>();
        meta->name = "users";
        meta->schema = "public";
        meta->columns.push_back(ColumnMetadata("id", "integer", 0, false, true));
        meta->columns.push_back(ColumnMetadata("email", "text", 0, true, false));
        schema["public.users"] = meta;

        catalog.seed_from_schema(schema);

        auto tables = catalog.get_tables();
        REQUIRE(tables.size() == 1);
        REQUIRE(tables[0].name == "public.users");

        auto cols = catalog.get_columns("public.users");
        REQUIRE(cols.size() == 2);

        bool found_id = false, found_email = false;
        for (const auto& col : cols) {
            if (col.column == "id") {
                found_id = true;
                REQUIRE(col.data_type == "integer");
                REQUIRE(col.is_primary_key);
                REQUIRE_FALSE(col.is_nullable);
            } else if (col.column == "email") {
                found_email = true;
                REQUIRE(col.data_type == "text");
                REQUIRE_FALSE(col.is_primary_key);
                REQUIRE(col.is_nullable);
            }
        }
        REQUIRE(found_id);
        REQUIRE(found_email);
    }

    SECTION("Stats aggregation") {
        DataCatalog catalog(default_config());

        auto a1 = make_analysis("customers");
        ClassificationResult cls;
        cls.classifications["email"] = ColumnClassification(
            "email", ClassificationType::PII_EMAIL, 0.9, "pattern");
        cls.classifications["name"] = ColumnClassification(
            "name", ClassificationType::NONE, 0.0, "");
        cls.classifications["phone"] = ColumnClassification(
            "phone", ClassificationType::PII_PHONE, 0.85, "pattern");

        catalog.record_classifications("testdb", "alice", a1, cls, {});

        auto stats = catalog.get_stats();
        REQUIRE(stats.total_tables == 1);
        REQUIRE(stats.total_columns == 3);
        REQUIRE(stats.pii_columns == 2);
        REQUIRE(stats.total_classifications_recorded == 1);
    }

    SECTION("Empty classification is ignored") {
        DataCatalog catalog(default_config());

        auto analysis = make_analysis("customers");
        ClassificationResult empty_cls;

        catalog.record_classifications("testdb", "alice", analysis, empty_cls, {});

        auto stats = catalog.get_stats();
        REQUIRE(stats.total_tables == 0);
        REQUIRE(stats.total_columns == 0);
    }

    SECTION("Table without schema uses bare name") {
        DataCatalog catalog(default_config());

        AnalysisResult analysis;
        analysis.statement_type = StatementType::SELECT;
        analysis.source_tables.push_back(TableRef{"logs"});

        auto cls = make_classification("level", ClassificationType::NONE);
        catalog.record_classifications("testdb", "alice", analysis, cls, {});

        auto tables = catalog.get_tables();
        REQUIRE(tables.size() == 1);
        REQUIRE(tables[0].name == "logs");
    }
}
