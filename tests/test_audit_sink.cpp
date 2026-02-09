#include <catch2/catch_test_macros.hpp>
#include "audit/audit_sink.hpp"
#include "audit/file_sink.hpp"
#include "audit/webhook_sink.hpp"
#include "audit/syslog_sink.hpp"
#include "audit/audit_emitter.hpp"
#include "core/types.hpp"

#include <filesystem>
#include <fstream>
#include <memory>
#include <thread>

using namespace sqlproxy;

namespace {

std::string read_file_contents(const std::string& path) {
    std::ifstream ifs(path);
    return std::string(std::istreambuf_iterator<char>(ifs),
                       std::istreambuf_iterator<char>());
}

} // anonymous namespace

// ============================================================================
// IAuditSink Interface Tests
// ============================================================================

TEST_CASE("Audit Sink: FileSink basic write", "[audit][sink]") {
    std::string test_file = "/tmp/test_file_sink_basic.jsonl";
    std::filesystem::remove(test_file);

    {
        FileSink::Config cfg;
        cfg.output_file = test_file;
        FileSink sink(cfg);

        REQUIRE(sink.name().find("file:") == 0);
        REQUIRE(sink.write("{\"event\":\"test\"}\n"));
        sink.flush();
    }

    auto contents = read_file_contents(test_file);
    REQUIRE(contents.find("test") != std::string::npos);
    std::filesystem::remove(test_file);
}

TEST_CASE("Audit Sink: FileSink tracks file size", "[audit][sink]") {
    std::string test_file = "/tmp/test_file_sink_size.jsonl";
    std::filesystem::remove(test_file);

    FileSink::Config cfg;
    cfg.output_file = test_file;
    FileSink sink(cfg);

    std::string line = "{\"event\":\"test\"}\n";
    (void)sink.write(line);
    sink.flush();

    REQUIRE(sink.current_file_size() >= line.size());

    sink.shutdown();
    std::filesystem::remove(test_file);
}

TEST_CASE("Audit Sink: WebhookSink construction", "[audit][sink]") {
    WebhookSink::Config cfg;
    cfg.url = "http://localhost:9999/webhook";
    cfg.batch_size = 10;

    WebhookSink sink(cfg);
    REQUIRE(sink.name().find("webhook:") == 0);
    // Write should buffer without throwing
    REQUIRE(sink.write("{\"event\":\"test\"}\n"));
}

TEST_CASE("Audit Sink: WebhookSink URL parsing", "[audit][sink]") {
    SECTION("HTTP URL") {
        WebhookSink::Config cfg;
        cfg.url = "http://example.com:8080/api/events";
        WebhookSink sink(cfg);
        REQUIRE(sink.name().find("webhook:") == 0);
    }

    SECTION("HTTPS URL") {
        WebhookSink::Config cfg;
        cfg.url = "https://siem.example.com/v1/ingest";
        WebhookSink sink(cfg);
        REQUIRE(sink.name().find("webhook:") == 0);
    }
}

TEST_CASE("Audit Sink: SyslogSink construction", "[audit][sink]") {
    SyslogSink::Config cfg;
    cfg.ident = "test-sql-proxy";
    SyslogSink sink(cfg);

    REQUIRE(sink.name().find("syslog:") == 0);
    REQUIRE(sink.write("{\"event\":\"test\"}\n"));
    REQUIRE(sink.records_written() == 1);
    sink.shutdown();
}

// ============================================================================
// AuditEmitter with sinks (heap-allocated — ring buffer is ~67MB)
// ============================================================================

TEST_CASE("Audit Sink: AuditEmitter backward-compatible constructor", "[audit][sink]") {
    std::string test_file = "/tmp/test_emitter_compat.jsonl";
    std::filesystem::remove(test_file);

    {
        auto emitter = std::make_unique<AuditEmitter>(test_file);
        auto stats = emitter->get_stats();
        REQUIRE(stats.active_sinks == 1);

        AuditRecord record;
        record.audit_id = "test-001";
        record.user = "admin";
        record.sql = "SELECT 1";
        record.database_name = "testdb";
        record.statement_type = StatementType::SELECT;
        emitter->emit(std::move(record));
        emitter->flush();

        stats = emitter->get_stats();
        REQUIRE(stats.total_emitted == 1);
        REQUIRE(stats.total_written == 1);
    }

    auto contents = read_file_contents(test_file);
    REQUIRE(contents.find("test-001") != std::string::npos);
    std::filesystem::remove(test_file);
}

TEST_CASE("Audit Sink: AuditEmitter config constructor with file sink", "[audit][sink]") {
    std::string test_file = "/tmp/test_emitter_config.jsonl";
    std::filesystem::remove(test_file);

    AuditConfig config;
    config.output_file = test_file;

    {
        auto emitter = std::make_unique<AuditEmitter>(config);
        auto stats = emitter->get_stats();
        REQUIRE(stats.active_sinks >= 1);

        AuditRecord record;
        record.audit_id = "config-001";
        record.user = "analyst";
        record.sql = "SELECT * FROM customers";
        record.database_name = "testdb";
        record.statement_type = StatementType::SELECT;
        emitter->emit(std::move(record));
        emitter->flush();

        stats = emitter->get_stats();
        REQUIRE(stats.total_emitted == 1);
    }

    auto contents = read_file_contents(test_file);
    REQUIRE(contents.find("config-001") != std::string::npos);
    std::filesystem::remove(test_file);
}

TEST_CASE("Audit Sink: AuditEmitter sink_write_failures tracked", "[audit][sink]") {
    std::string test_file = "/tmp/test_emitter_failures.jsonl";
    std::filesystem::remove(test_file);

    auto emitter = std::make_unique<AuditEmitter>(test_file);
    auto stats = emitter->get_stats();
    REQUIRE(stats.sink_write_failures == 0);
    std::filesystem::remove(test_file);
}

TEST_CASE("Audit Sink: AuditEmitter trace fields in JSON", "[audit][sink]") {
    std::string test_file = "/tmp/test_emitter_trace.jsonl";
    std::filesystem::remove(test_file);

    {
        auto emitter = std::make_unique<AuditEmitter>(test_file);

        AuditRecord record;
        record.audit_id = "trace-001";
        record.trace_id = "00112233445566778899aabbccddeeff";
        record.span_id = "aabbccddeeff0011";
        record.parent_span_id = "1122334455667788";
        record.user = "admin";
        record.sql = "SELECT 1";
        record.database_name = "testdb";
        record.statement_type = StatementType::SELECT;
        emitter->emit(std::move(record));
        emitter->flush();
    }

    auto contents = read_file_contents(test_file);
    REQUIRE(contents.find("trace_id") != std::string::npos);
    REQUIRE(contents.find("00112233445566778899aabbccddeeff") != std::string::npos);
    REQUIRE(contents.find("span_id") != std::string::npos);
    REQUIRE(contents.find("parent_span_id") != std::string::npos);
    std::filesystem::remove(test_file);
}
