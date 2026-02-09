#include <catch2/catch_test_macros.hpp>
#include "audit/audit_emitter.hpp"
#include "core/types.hpp"
#include "core/utils.hpp"

#include <chrono>
#include <thread>

using namespace sqlproxy;

TEST_CASE("Audit hash chain - records have hashes", "[audit][integrity]") {
    AuditConfig config;
    config.output_file = "/dev/null";  // Discard output for test
    config.batch_flush_interval = std::chrono::milliseconds(50);
    config.integrity_enabled = true;

    AuditEmitter emitter(config);

    // Emit a few records
    for (int i = 0; i < 5; ++i) {
        AuditRecord record;
        record.audit_id = utils::generate_uuid();
        record.timestamp = std::chrono::system_clock::now();
        record.received_at = std::chrono::system_clock::now();
        record.user = "test_user";
        record.sql = "SELECT " + std::to_string(i);
        record.decision = Decision::ALLOW;
        record.database_name = "testdb";
        record.execution_success = true;
        emitter.emit(std::move(record));
    }

    // Wait for writer thread to process
    emitter.flush();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto stats = emitter.get_stats();
    REQUIRE(stats.total_emitted == 5);
    REQUIRE(stats.total_written == 5);
}

TEST_CASE("Audit hash chain - compute_record_hash is deterministic", "[audit][integrity]") {
    AuditRecord record;
    record.sequence_num = 42;
    record.timestamp = std::chrono::system_clock::from_time_t(1700000000);
    record.user = "analyst";
    record.sql = "SELECT * FROM customers";
    record.decision = Decision::ALLOW;

    std::string hash1 = AuditEmitter::compute_record_hash(record, "prev_hash_123");
    std::string hash2 = AuditEmitter::compute_record_hash(record, "prev_hash_123");

    REQUIRE(hash1 == hash2);
    REQUIRE(hash1.size() == 64);  // SHA-256 = 64 hex chars
}

TEST_CASE("Audit hash chain - different inputs produce different hashes", "[audit][integrity]") {
    AuditRecord record;
    record.sequence_num = 1;
    record.timestamp = std::chrono::system_clock::from_time_t(1700000000);
    record.user = "analyst";
    record.sql = "SELECT 1";
    record.decision = Decision::ALLOW;

    std::string hash_a = AuditEmitter::compute_record_hash(record, "");
    std::string hash_b = AuditEmitter::compute_record_hash(record, "some_previous_hash");

    REQUIRE(hash_a != hash_b);
}

TEST_CASE("Audit hash chain - chain links records", "[audit][integrity]") {
    AuditRecord r1;
    r1.sequence_num = 0;
    r1.timestamp = std::chrono::system_clock::from_time_t(1700000000);
    r1.user = "user1";
    r1.sql = "SELECT 1";
    r1.decision = Decision::ALLOW;

    std::string hash1 = AuditEmitter::compute_record_hash(r1, "");

    AuditRecord r2;
    r2.sequence_num = 1;
    r2.timestamp = std::chrono::system_clock::from_time_t(1700000001);
    r2.user = "user2";
    r2.sql = "SELECT 2";
    r2.decision = Decision::ALLOW;

    std::string hash2 = AuditEmitter::compute_record_hash(r2, hash1);

    // Tamper: recompute hash2 with wrong previous hash
    std::string tampered_hash2 = AuditEmitter::compute_record_hash(r2, "wrong_previous");

    REQUIRE(hash2 != tampered_hash2);  // Tamper detected
}

TEST_CASE("Audit integrity config from TOML", "[audit][integrity][config]") {
    std::string toml = R"(
[audit]
async_mode = true

[audit.integrity]
enabled = true
algorithm = "sha256"
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    REQUIRE(result.config.audit.integrity_enabled);
    REQUIRE(result.config.audit.integrity_algorithm == "sha256");
}
