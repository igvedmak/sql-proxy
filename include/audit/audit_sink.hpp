#pragma once

#include <string>
#include <string_view>

namespace sqlproxy {

/**
 * @brief Abstract interface for audit output destinations
 *
 * Each sink receives serialized JSON records from the AuditEmitter's
 * writer thread. Implementations are single-threaded (only called from
 * the writer thread), so no internal locking is needed.
 */
class IAuditSink {
public:
    virtual ~IAuditSink() = default;

    /// Write a single JSON-serialized audit record. Returns true on success.
    [[nodiscard]] virtual bool write(std::string_view json_line) = 0;

    /// Flush any buffered data to the underlying storage.
    virtual void flush() = 0;

    /// Graceful shutdown (drain buffers, close handles).
    virtual void shutdown() = 0;

    /// Human-readable sink name for logging (e.g. "file:/app/logs/audit.jsonl")
    [[nodiscard]] virtual std::string name() const = 0;
};

} // namespace sqlproxy
