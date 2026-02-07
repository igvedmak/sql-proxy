#pragma once

#include "audit/ring_buffer.hpp"
#include "core/types.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>

namespace sqlproxy {

/**
 * @brief High-performance async audit emitter
 *
 * Decouples audit record production from file I/O using a lock-free
 * MPSC ring buffer and a dedicated background writer thread.
 *
 * Producers (HTTP handler threads) call emit() which is non-blocking
 * (~50ns CAS enqueue). The background writer drains the ring buffer
 * in batches and writes to a JSONL file.
 *
 * Performance target: >10K req/sec sustained audit throughput.
 *
 * Architecture:
 *   [Thread 1] --emit()--> [Ring Buffer] --drain()--> [Writer Thread] --> [File]
 *   [Thread 2] --emit()-->
 *   [Thread N] --emit()-->
 */
class AuditEmitter {
public:
    /**
     * @brief Construct audit emitter from AuditConfig
     * @param config Audit configuration (file path, buffer size, flush interval)
     *
     * Starts the background writer thread immediately.
     */
    explicit AuditEmitter(const AuditConfig& config);

    /**
     * @brief Backward-compatible constructor from file path
     * @param output_file Path to audit log file (JSONL format)
     *
     * Uses default AuditConfig values with the specified output file.
     */
    explicit AuditEmitter(std::string output_file);

    /**
     * @brief Destructor - signals shutdown, drains remaining records, joins writer thread
     */
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
     *
     * Safe to call from multiple threads concurrently.
     * Safe to call after shutdown (record is silently dropped).
     *
     * @param record Audit record to emit (taken by value for move optimization)
     */
    void emit(AuditRecord record);

    /**
     * @brief Force flush all pending records to disk
     *
     * Signals the writer thread to wake up and drain immediately.
     * Blocks until the writer has completed one full drain cycle.
     */
    void flush();

    /**
     * @brief Graceful shutdown
     *
     * Signals the writer thread to stop, waits for it to drain
     * remaining records and join. After shutdown, emit() calls
     * are silently dropped.
     */
    void shutdown();

    /**
     * @brief Runtime statistics
     */
    struct Stats {
        uint64_t total_emitted;      ///< Records pushed to ring buffer
        uint64_t total_written;      ///< Records written to file
        uint64_t overflow_dropped;   ///< Records dropped (buffer full)
        uint64_t flush_count;        ///< Number of batch flushes performed
    };

    /**
     * @brief Get current statistics (lock-free reads)
     */
    [[nodiscard]] Stats get_stats() const;

private:
    /**
     * @brief Background writer thread main loop
     *
     * Wakes every batch_flush_interval_ or on flush()/shutdown() signal.
     * Drains ring buffer in batches of up to kMaxBatchSize records.
     * Calls fsync periodically (every kFsyncInterval batches).
     * On shutdown: drains all remaining records, flushes, and closes file.
     */
    void writer_thread_func();

    /**
     * @brief Convert audit record to JSON string (JSONL format)
     */
    std::string to_json(const AuditRecord& record);

    /**
     * @brief Initialize file stream and start writer thread
     */
    void start(const std::string& output_file);

    // -- Constants --
    static constexpr size_t kMaxBatchSize = 1000;
    static constexpr size_t kFsyncInterval = 10;  // fsync every N batches

    // -- Ring buffer: decouples producers from writer --
    MPSCRingBuffer<AuditRecord, 65536> ring_buffer_;

    // -- Background writer thread --
    std::thread writer_thread_;
    std::atomic<bool> running_{false};

    // -- Flush synchronization --
    std::mutex flush_mutex_;
    std::condition_variable flush_cv_;
    std::atomic<bool> flush_requested_{false};

    // -- File output --
    std::ofstream file_stream_;
    std::string output_file_;
    std::chrono::milliseconds batch_flush_interval_{100};

    // -- Stats (atomic for lock-free reads from any thread) --
    std::atomic<uint64_t> total_emitted_{0};
    std::atomic<uint64_t> total_written_{0};
    std::atomic<uint64_t> flush_count_{0};
    std::atomic<uint64_t> sequence_counter_{0};
};

} // namespace sqlproxy
