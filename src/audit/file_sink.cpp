#include "audit/file_sink.hpp"
#include <filesystem>
#include <format>
#include <stdexcept>

namespace sqlproxy {

FileSink::FileSink(const Config& config)
    : config_(config),
      last_rotation_time_(std::chrono::system_clock::now()) {
    file_stream_.open(config_.output_file, std::ios::app);
    if (!file_stream_.is_open()) {
        throw std::runtime_error("Failed to open audit file: " + config_.output_file);
    }

    // Determine current file size for size-based rotation
    std::error_code ec;
    auto file_size = std::filesystem::file_size(config_.output_file, ec);
    if (!ec) {
        current_file_size_ = static_cast<size_t>(file_size);
    }
}

FileSink::~FileSink() {
    shutdown();
}

bool FileSink::write(std::string_view json_line) {
    check_rotation();
    file_stream_.write(json_line.data(), static_cast<std::streamsize>(json_line.size()));
    current_file_size_ += json_line.size();
    return file_stream_.good();
}

void FileSink::flush() {
    file_stream_.flush();
}

void FileSink::shutdown() {
    if (file_stream_.is_open()) {
        file_stream_.flush();
        file_stream_.close();
    }
}

std::string FileSink::name() const {
    return "file:" + config_.output_file;
}

void FileSink::check_rotation() {
    bool need_rotate = false;

    if (config_.size_based_rotation &&
        current_file_size_ >= config_.max_file_size_bytes) {
        need_rotate = true;
    }

    if (config_.time_based_rotation) {
        auto now = std::chrono::system_clock::now();
        if (now - last_rotation_time_ >= config_.rotation_interval) {
            need_rotate = true;
        }
    }

    if (need_rotate) {
        rotate_file();
    }
}

void FileSink::rotate_file() {
    file_stream_.flush();
    file_stream_.close();

    std::error_code ec;

    // Delete the oldest file if it exceeds max_files
    auto oldest = std::format("{}.{}", config_.output_file, config_.max_files);
    std::filesystem::remove(oldest, ec);

    // Shift existing rotated files: .N -> .N+1
    for (int i = config_.max_files - 1; i >= 1; --i) {
        auto old_name = std::format("{}.{}", config_.output_file, i);
        auto new_name = std::format("{}.{}", config_.output_file, i + 1);
        std::filesystem::rename(old_name, new_name, ec);
        // Ignore errors for missing files
    }

    // Rename current file -> .1
    std::filesystem::rename(config_.output_file, config_.output_file + ".1", ec);

    // Reopen fresh file
    file_stream_.open(config_.output_file, std::ios::app);
    current_file_size_ = 0;
    last_rotation_time_ = std::chrono::system_clock::now();
    ++rotation_count_;
}

} // namespace sqlproxy
