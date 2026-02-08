#include "audit/syslog_sink.hpp"
#include <syslog.h>

namespace sqlproxy {

SyslogSink::SyslogSink(const Config& config)
    : config_(config) {
    openlog(config_.ident.c_str(), LOG_NDELAY | LOG_PID, config_.facility);
    open_ = true;
}

SyslogSink::~SyslogSink() {
    shutdown();
}

bool SyslogSink::write(std::string_view json_line) {
    if (!open_) return false;

    // syslog expects null-terminated string
    std::string msg(json_line);
    // Strip trailing newline if present (syslog adds its own)
    if (!msg.empty() && msg.back() == '\n') {
        msg.pop_back();
    }

    syslog(config_.priority, "%s", msg.c_str());
    ++records_written_;
    return true;
}

void SyslogSink::flush() {
    // syslog is unbuffered — nothing to flush
}

void SyslogSink::shutdown() {
    if (open_) {
        closelog();
        open_ = false;
    }
}

std::string SyslogSink::name() const {
    return "syslog:" + config_.ident;
}

} // namespace sqlproxy
