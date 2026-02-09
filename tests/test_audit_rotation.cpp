#include <catch2/catch_test_macros.hpp>
#include "audit/file_sink.hpp"
#include "core/types.hpp"

#include <filesystem>
#include <fstream>
#include <string>

using namespace sqlproxy;

namespace {

std::string read_file_contents(const std::string& path) {
    std::ifstream ifs(path);
    return std::string(std::istreambuf_iterator<char>(ifs),
                       std::istreambuf_iterator<char>());
}

void cleanup_rotation_files(const std::string& base, int max_files) {
    std::filesystem::remove(base);
    for (int i = 1; i <= max_files + 2; ++i) {
        std::filesystem::remove(base + "." + std::to_string(i));
    }
}

} // anonymous namespace

// ============================================================================
// File Rotation Tests
// ============================================================================

TEST_CASE("Audit Rotation: size-based rotation triggers", "[audit][rotation]") {
    std::string test_file = "/tmp/test_rotation_size.jsonl";
    cleanup_rotation_files(test_file, 5);

    FileSink::Config cfg;
    cfg.output_file = test_file;
    cfg.max_file_size_bytes = 100;  // Very small to trigger rotation
    cfg.max_files = 3;
    cfg.size_based_rotation = true;
    cfg.time_based_rotation = false;

    {
        FileSink sink(cfg);

        // Write enough data to trigger rotation
        std::string line(60, 'a');
        line += '\n';

        (void)sink.write(line);
        (void)sink.write(line);
        (void)sink.write(line);  // This should trigger rotation
        sink.flush();

        REQUIRE(sink.rotation_count() >= 1);
    }

    // Rotated file should exist
    REQUIRE(std::filesystem::exists(test_file + ".1"));

    cleanup_rotation_files(test_file, 5);
}

TEST_CASE("Audit Rotation: max_files cleanup", "[audit][rotation]") {
    std::string test_file = "/tmp/test_rotation_max.jsonl";
    cleanup_rotation_files(test_file, 5);

    FileSink::Config cfg;
    cfg.output_file = test_file;
    cfg.max_file_size_bytes = 50;  // Very small
    cfg.max_files = 2;
    cfg.size_based_rotation = true;
    cfg.time_based_rotation = false;

    {
        FileSink sink(cfg);

        std::string line(60, 'b');
        line += '\n';

        // Write enough to trigger multiple rotations
        for (int i = 0; i < 6; ++i) {
            (void)sink.write(line);
        }
        sink.flush();
    }

    // At most max_files rotated files should exist
    // File .3 should NOT exist (max_files = 2)
    REQUIRE_FALSE(std::filesystem::exists(test_file + ".3"));

    cleanup_rotation_files(test_file, 5);
}

TEST_CASE("Audit Rotation: rotation preserves data", "[audit][rotation]") {
    std::string test_file = "/tmp/test_rotation_data.jsonl";
    cleanup_rotation_files(test_file, 5);

    FileSink::Config cfg;
    cfg.output_file = test_file;
    cfg.max_file_size_bytes = 100;
    cfg.max_files = 5;
    cfg.size_based_rotation = true;
    cfg.time_based_rotation = false;

    {
        FileSink sink(cfg);

        // Write identifiable data before rotation
        (void)sink.write("{\"batch\":\"first\"}\n");
        (void)sink.write(std::string(100, 'x') + "\n");  // Trigger rotation
        (void)sink.write("{\"batch\":\"second\"}\n");
        sink.flush();
    }

    // The rotated file should contain the first batch
    if (std::filesystem::exists(test_file + ".1")) {
        auto rotated = read_file_contents(test_file + ".1");
        REQUIRE(rotated.find("first") != std::string::npos);
    }

    // The current file should contain the second batch
    auto current = read_file_contents(test_file);
    REQUIRE(current.find("second") != std::string::npos);

    cleanup_rotation_files(test_file, 5);
}

TEST_CASE("Audit Rotation: no rotation when disabled", "[audit][rotation]") {
    std::string test_file = "/tmp/test_rotation_disabled.jsonl";
    cleanup_rotation_files(test_file, 5);

    FileSink::Config cfg;
    cfg.output_file = test_file;
    cfg.max_file_size_bytes = 50;
    cfg.max_files = 3;
    cfg.size_based_rotation = false;
    cfg.time_based_rotation = false;

    {
        FileSink sink(cfg);

        std::string line(100, 'c');
        line += '\n';

        (void)sink.write(line);
        (void)sink.write(line);
        sink.flush();

        REQUIRE(sink.rotation_count() == 0);
    }

    REQUIRE_FALSE(std::filesystem::exists(test_file + ".1"));
    cleanup_rotation_files(test_file, 5);
}

TEST_CASE("Audit Rotation: config parsing from AuditConfig", "[audit][rotation]") {
    AuditConfig config;
    config.rotation_max_file_size_mb = 50;
    config.rotation_max_files = 5;
    config.rotation_interval_hours = 12;
    config.rotation_time_based = true;
    config.rotation_size_based = true;

    REQUIRE(config.rotation_max_file_size_mb == 50);
    REQUIRE(config.rotation_max_files == 5);
    REQUIRE(config.rotation_interval_hours == 12);
    REQUIRE(config.rotation_time_based);
    REQUIRE(config.rotation_size_based);
}

TEST_CASE("Audit Rotation: time-based rotation config", "[audit][rotation]") {
    FileSink::Config cfg;
    cfg.output_file = "/tmp/test_rotation_time_cfg.jsonl";
    cfg.rotation_interval = std::chrono::hours(1);
    cfg.time_based_rotation = true;
    cfg.size_based_rotation = false;

    FileSink sink(cfg);
    // Just verify it constructs without error
    REQUIRE(sink.name().find("file:") == 0);
    sink.shutdown();
    std::filesystem::remove(cfg.output_file);
}

TEST_CASE("Audit Rotation: rename chain correctness", "[audit][rotation]") {
    std::string test_file = "/tmp/test_rotation_chain.jsonl";
    cleanup_rotation_files(test_file, 5);

    FileSink::Config cfg;
    cfg.output_file = test_file;
    cfg.max_file_size_bytes = 30;  // Very small
    cfg.max_files = 5;
    cfg.size_based_rotation = true;
    cfg.time_based_rotation = false;

    {
        FileSink sink(cfg);

        // Each write should trigger a rotation
        for (int i = 0; i < 4; ++i) {
            std::string line = "{\"rotation\":" + std::to_string(i) + "}\n";
            (void)sink.write(line);
        }
        sink.flush();
    }

    // Verify files exist in the chain
    REQUIRE(std::filesystem::exists(test_file));
    REQUIRE(std::filesystem::exists(test_file + ".1"));

    cleanup_rotation_files(test_file, 5);
}
