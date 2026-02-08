#pragma once

#include "audit/audit_sink.hpp"
#include <chrono>
#include <cstddef>
#include <fstream>
#include <string>

namespace sqlproxy {

/**
 * @brief File-based audit sink with size and time-based rotation
 *
 * Writes JSONL records to a file. Supports automatic rotation based on
 * file size and/or time interval. Rotated files are named with numeric
 * suffixes: audit.jsonl.1, audit.jsonl.2, etc. Oldest files beyond
 * max_files are deleted.
 *
 * Called exclusively from the AuditEmitter writer thread — no locking needed.
 */
class FileSink : public IAuditSink {
public:
    struct Config {
        std::string output_file = "audit.jsonl";
        size_t max_file_size_bytes = 100ULL * 1024 * 1024;  // 100MB
        int max_files = 10;
        std::chrono::hours rotation_interval{24};
        bool time_based_rotation = true;
        bool size_based_rotation = true;
    };

    explicit FileSink(const Config& config);
    ~FileSink() override;

    [[nodiscard]] bool write(std::string_view json_line) override;
    void flush() override;
    void shutdown() override;
    [[nodiscard]] std::string name() const override;

    /// Number of rotations performed (for stats/testing)
    [[nodiscard]] size_t rotation_count() const { return rotation_count_; }

    /// Current file size in bytes
    [[nodiscard]] size_t current_file_size() const { return current_file_size_; }

private:
    void check_rotation();
    void rotate_file();

    Config config_;
    std::ofstream file_stream_;
    size_t current_file_size_ = 0;
    size_t rotation_count_ = 0;
    std::chrono::system_clock::time_point last_rotation_time_;
};

} // namespace sqlproxy
