#pragma once

#include "audit/audit_sink.hpp"
#include <chrono>
#include <string>
#include <vector>

namespace sqlproxy {

/**
 * @brief HTTP POST audit sink for shipping records to external systems
 *
 * Buffers records and batch-POSTs them as NDJSON to a configured URL.
 * Uses cpp-httplib client (already a project dependency).
 * Failures increment a counter but never throw or block the writer thread.
 */
class WebhookSink : public IAuditSink {
public:
    struct Config {
        std::string url;
        std::string auth_header;
        std::chrono::milliseconds timeout{5000};
        int max_retries = 3;
        size_t batch_size = 100;
        std::string content_type = "application/x-ndjson";
    };

    explicit WebhookSink(const Config& config);
    ~WebhookSink() override;

    [[nodiscard]] bool write(std::string_view json_line) override;
    void flush() override;
    void shutdown() override;
    [[nodiscard]] std::string name() const override;

    [[nodiscard]] uint64_t send_failures() const { return send_failures_; }
    [[nodiscard]] uint64_t batches_sent() const { return batches_sent_; }

private:
    void send_batch();

    Config config_;
    std::vector<std::string> buffer_;
    uint64_t send_failures_ = 0;
    uint64_t batches_sent_ = 0;

    // Parsed from URL
    std::string host_;
    std::string path_;
    int port_ = 443;
    bool use_ssl_ = true;
};

} // namespace sqlproxy
