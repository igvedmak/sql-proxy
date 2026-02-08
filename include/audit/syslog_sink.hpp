#pragma once

#include "audit/audit_sink.hpp"
#include <cstdint>
#include <string>

namespace sqlproxy {

/**
 * @brief POSIX syslog audit sink
 *
 * Writes audit records to the local syslog facility.
 * Zero external dependencies (uses POSIX syslog(3)).
 */
class SyslogSink : public IAuditSink {
public:
    struct Config {
        std::string ident = "sql-proxy";
        int facility = 128;   // LOG_LOCAL0 = (16 << 3) = 128
        int priority = 6;     // LOG_INFO = 6
    };

    explicit SyslogSink(const Config& config);
    ~SyslogSink() override;

    [[nodiscard]] bool write(std::string_view json_line) override;
    void flush() override;
    void shutdown() override;
    [[nodiscard]] std::string name() const override;

    [[nodiscard]] uint64_t records_written() const { return records_written_; }

private:
    Config config_;
    uint64_t records_written_ = 0;
    bool open_ = false;
};

} // namespace sqlproxy
