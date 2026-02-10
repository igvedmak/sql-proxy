#pragma once

#include "audit/ring_buffer.hpp"
#include "audit/audit_sink.hpp"
#include "audit/audit_encryptor.hpp"
#include "core/types.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace sqlproxy {

/**
 * @brief High-performance async audit emitter
 *
 * Decouples audit record production from I/O using a lock-free
 * MPSC ring buffer and a dedicated background writer thread.
 *
 * Producers (HTTP handler threads) call emit() which is non-blocking
 * (~50ns CAS enqueue). The background writer drains the ring buffer
 * in batches and writes to one or more IAuditSink implementations.
 *
 * Performance target: >10K req/sec sustained audit throughput.
 *
 * Architecture:
 *   [Thread 1] --emit()--> [Ring Buffer] --drain()--> [Writer Thread] --> [Sink 1: File]
 *   [Thread 2] --emit()-->                                            --> [Sink 2: Webhook]
 *   [Thread N] --emit()-->                                            --> [Sink N: Syslog]
 */
class AuditEmitter {
public:
    /**
     * @brief Construct audit emitter from AuditConfig
     *
     * Creates sinks based on config: FileSink always (with rotation),
     * plus optional WebhookSink and SyslogSink if enabled.
     * Starts the background writer thread immediately.
     */
    explicit AuditEmitter(const AuditConfig& config);

    /**
     * @brief Backward-compatible constructor from file path
     *
     * Creates a single FileSink with default rotation settings.
     */
    explicit AuditEmitter(std::string output_file);

    ~AuditEmitter();

    // Non-copyable, non-movable (owns thread and ring buffer)
    AuditEmitter(const AuditEmitter&) = delete;
    AuditEmitter& operator=(const AuditEmitter&) = delete;
    AuditEmitter(AuditEmitter&&) = delete;
    AuditEmitter& operator=(AuditEmitter&&) = delete;

    /**
     * @brief Emit an audit record (non-blocking, ~50ns)
     *
     * Assigns a monotonic sequence number, then enqueues the record
     * into the ring buffer. If the buffer is full, the record is dropped
     * and the overflow counter is incremented.
     */
    void emit(AuditRecord record);

    /// Force flush all pending records to all sinks
    void flush();

    /// Graceful shutdown — drain, flush, and close all sinks
    void shutdown();

    struct Stats {
        uint64_t total_emitted;      ///< Records pushed to ring buffer
        uint64_t total_written;      ///< Records written to sinks
        uint64_t overflow_dropped;   ///< Records dropped (buffer full)
        uint64_t flush_count;        ///< Number of batch flushes performed
        uint64_t sink_write_failures;///< Failed sink write attempts
        size_t active_sinks;         ///< Number of active sinks
    };

    [[nodiscard]] Stats get_stats() const;

    static std::string compute_record_hash(const AuditRecord& record, const std::string& prev_hash);

    void set_encryptor(std::shared_ptr<AuditEncryptor> encryptor) {
        encryptor_ = std::move(encryptor);
    }

    [[nodiscard]] std::shared_ptr<AuditEncryptor> get_encryptor() const {
        return encryptor_;
    }

private:
    void writer_thread_func();
    std::string to_json(const AuditRecord& record);
    void start();

    void write_to_sinks(std::string_view data);
    void flush_sinks();
    void shutdown_sinks();

    // -- Constants --
    static constexpr size_t kMaxBatchSize = 1000;
    static constexpr size_t kFsyncInterval = 10;

    // -- Sinks --
    std::vector<std::unique_ptr<IAuditSink>> sinks_;

    // -- Ring buffer --
    MPSCRingBuffer<AuditRecord, 65536> ring_buffer_;

    // -- Background writer thread --
    std::thread writer_thread_;
    std::atomic<bool> running_{false};

    // -- Flush synchronization --
    std::mutex flush_mutex_;
    std::condition_variable flush_cv_;
    std::atomic<bool> flush_requested_{false};

    // -- Config --
    std::chrono::milliseconds batch_flush_interval_{100};

    // -- Stats --
    std::atomic<uint64_t> total_emitted_{0};
    std::atomic<uint64_t> total_written_{0};
    std::atomic<uint64_t> flush_count_{0};
    std::atomic<uint64_t> sink_write_failures_{0};
    std::atomic<uint64_t> sequence_counter_{0};

    // -- Hash chain (writer thread only, no sync needed) --
    bool integrity_enabled_{true};
    std::string previous_hash_;

    // -- Audit encryption (writer thread only) --
    std::shared_ptr<AuditEncryptor> encryptor_;
};

} // namespace sqlproxy
