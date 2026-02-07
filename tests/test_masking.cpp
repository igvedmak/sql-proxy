#include <catch2/catch_test_macros.hpp>
#include "core/masking.hpp"

using namespace sqlproxy;

// ============================================================================
// MaskingEngine::mask_value tests
// ============================================================================

TEST_CASE("Masking NONE returns original value", "[masking]") {
    CHECK(MaskingEngine::mask_value("hello@example.com", MaskingAction::NONE) == "hello@example.com");
    CHECK(MaskingEngine::mask_value("", MaskingAction::NONE).empty());
}

TEST_CASE("Masking REDACT replaces entire value", "[masking]") {
    CHECK(MaskingEngine::mask_value("hello@example.com", MaskingAction::REDACT) == "***REDACTED***");
    CHECK(MaskingEngine::mask_value("short", MaskingAction::REDACT) == "***REDACTED***");
    CHECK(MaskingEngine::mask_value("", MaskingAction::REDACT) == "***REDACTED***");
}

TEST_CASE("Masking PARTIAL shows prefix and suffix", "[masking]") {
    // "hello@example.com" (17 chars) with prefix=3, suffix=3 => "hel***com"
    auto result = MaskingEngine::mask_value("hello@example.com", MaskingAction::PARTIAL, 3, 3);
    CHECK(result == "hel***com");

    // Custom prefix/suffix
    result = MaskingEngine::mask_value("alice@company.org", MaskingAction::PARTIAL, 5, 4);
    CHECK(result == "alice***.org");
}

TEST_CASE("Masking PARTIAL falls back to REDACT for short values", "[masking]") {
    // "abc" (3 chars) with prefix=3, suffix=3 => too short => REDACT
    CHECK(MaskingEngine::mask_value("abc", MaskingAction::PARTIAL, 3, 3) == "***REDACTED***");
    CHECK(MaskingEngine::mask_value("ab", MaskingAction::PARTIAL, 1, 2) == "***REDACTED***");
}

TEST_CASE("Masking HASH produces deterministic 16-hex output", "[masking]") {
    auto hash1 = MaskingEngine::mask_value("test@example.com", MaskingAction::HASH);
    auto hash2 = MaskingEngine::mask_value("test@example.com", MaskingAction::HASH);

    CHECK(hash1 == hash2);  // Deterministic
    CHECK(hash1.size() == 16);  // 16 hex chars

    // All hex characters
    for (char c : hash1) {
        CHECK(((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
    }

    // Different inputs produce different hashes
    auto hash3 = MaskingEngine::mask_value("other@example.com", MaskingAction::HASH);
    CHECK(hash1 != hash3);
}

TEST_CASE("Masking NULLIFY replaces with NULL", "[masking]") {
    CHECK(MaskingEngine::mask_value("anything", MaskingAction::NULLIFY) == "NULL");
    CHECK(MaskingEngine::mask_value("", MaskingAction::NULLIFY) == "NULL");
}

// ============================================================================
// MaskingEngine::apply tests
// ============================================================================

TEST_CASE("Masking apply with no decisions returns empty records", "[masking]") {
    QueryResult result;
    result.column_names = {"id", "email"};
    result.rows = {{"1", "alice@test.com"}};
    std::vector<ColumnPolicyDecision> empty;

    auto records = MaskingEngine::apply(result, empty);
    CHECK(records.empty());
    CHECK(result.rows[0][1] == "alice@test.com");  // Unchanged
}

TEST_CASE("Masking apply with NONE masking leaves data unchanged", "[masking]") {
    QueryResult result;
    result.column_names = {"id", "email"};
    result.rows = {{"1", "alice@test.com"}};

    ColumnPolicyDecision d;
    d.column_name = "email";
    d.decision = Decision::ALLOW;
    d.masking = MaskingAction::NONE;
    std::vector<ColumnPolicyDecision> decisions = {d};

    auto records = MaskingEngine::apply(result, decisions);
    CHECK(records.empty());
    CHECK(result.rows[0][1] == "alice@test.com");
}

TEST_CASE("Masking apply with REDACT masks column data", "[masking]") {
    QueryResult result;
    result.column_names = {"id", "email", "name"};
    result.rows = {
        {"1", "alice@test.com", "Alice"},
        {"2", "bob@test.com", "Bob"},
    };

    ColumnPolicyDecision d;
    d.column_name = "email";
    d.decision = Decision::ALLOW;
    d.masking = MaskingAction::REDACT;
    d.matched_policy = "redact_email";
    std::vector<ColumnPolicyDecision> decisions = {d};

    auto records = MaskingEngine::apply(result, decisions);
    REQUIRE(records.size() == 1);
    CHECK(records[0].column_name == "email");
    CHECK(records[0].action == MaskingAction::REDACT);
    CHECK(records[0].matched_policy == "redact_email");

    // Data should be masked
    CHECK(result.rows[0][1] == "***REDACTED***");
    CHECK(result.rows[1][1] == "***REDACTED***");
    // Other columns unchanged
    CHECK(result.rows[0][0] == "1");
    CHECK(result.rows[0][2] == "Alice");
}

TEST_CASE("Masking apply with multiple columns", "[masking]") {
    QueryResult result;
    result.column_names = {"id", "email", "phone"};
    result.rows = {
        {"1", "alice@test.com", "555-1234"},
        {"2", "bob@test.com", "555-5678"},
    };

    std::vector<ColumnPolicyDecision> decisions = {
        {"id", Decision::ALLOW, MaskingAction::NONE, ""},
        {"email", Decision::ALLOW, MaskingAction::PARTIAL, "mask_email", 3, 4},
        {"phone", Decision::ALLOW, MaskingAction::HASH, "hash_phone"},
    };

    auto records = MaskingEngine::apply(result, decisions);
    CHECK(records.size() == 2);  // email and phone

    // ID unchanged
    CHECK(result.rows[0][0] == "1");

    // Email partially masked
    CHECK(result.rows[0][1] == "ali***.com");

    // Phone hashed (16 hex chars)
    CHECK(result.rows[0][2].size() == 16);
}

TEST_CASE("Masking skips BLOCK decisions (only masks ALLOW)", "[masking]") {
    QueryResult result;
    result.column_names = {"id", "ssn"};
    result.rows = {{"1", "123-45-6789"}};

    ColumnPolicyDecision d;
    d.column_name = "ssn";
    d.decision = Decision::BLOCK;  // BLOCK, not ALLOW
    d.masking = MaskingAction::REDACT;
    std::vector<ColumnPolicyDecision> decisions = {d};

    auto records = MaskingEngine::apply(result, decisions);
    CHECK(records.empty());  // No masking applied (BLOCK columns should be removed by pipeline)
    CHECK(result.rows[0][1] == "123-45-6789");  // Data unchanged
}
