#include "audit/audit_emitter.hpp"
#include "core/utils.hpp"
#include <sstream>
#include <iomanip>
#include <vector>

namespace sqlproxy {

// ============================================================================
// Construction / Destruction
// ============================================================================

AuditEmitter::AuditEmitter(const AuditConfig& config)
    : batch_flush_interval_(config.batch_flush_interval) {
    start(config.output_file);
}

AuditEmitter::AuditEmitter(std::string output_file)
    : batch_flush_interval_(100) {
    start(output_file);
}

void AuditEmitter::start(const std::string& output_file) {
    output_file_ = output_file;

    file_stream_.open(output_file_, std::ios::app);
    if (!file_stream_.is_open()) {
        throw std::runtime_error("Failed to open audit file: " + output_file_);
    }

    // Start background writer thread
    running_.store(true, std::memory_order_release);
    writer_thread_ = std::thread(&AuditEmitter::writer_thread_func, this);
}

AuditEmitter::~AuditEmitter() {
    shutdown();
}

// ============================================================================
// Public Interface
// ============================================================================

void AuditEmitter::emit(const AuditRecord& record) {
    // Silently drop if already shut down
    if (!running_.load(std::memory_order_acquire)) {
        return;
    }

    // Assign monotonic sequence number (thread-safe, lock-free)
    AuditRecord mutable_record = record;
    mutable_record.sequence_num = sequence_counter_.fetch_add(1, std::memory_order_relaxed);

    // Non-blocking enqueue into ring buffer (~50ns)
    // If buffer is full, try_push returns false and the ring buffer
    // increments its internal overflow counter.
    (void)ring_buffer_.try_push(std::move(mutable_record));

    total_emitted_.fetch_add(1, std::memory_order_relaxed);
}

void AuditEmitter::flush() {
    if (!running_.load(std::memory_order_acquire)) {
        return;
    }

    // Signal the writer thread to wake up and drain
    {
        std::lock_guard<std::mutex> lock(flush_mutex_);
        flush_requested_.store(true, std::memory_order_release);
    }
    flush_cv_.notify_one();

    // Wait for the writer to complete the flush cycle.
    // We spin-check flush_requested_ being cleared by the writer.
    // This is acceptable because flush() is infrequent (shutdown, explicit flush).
    while (flush_requested_.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));

        // Break if writer thread has stopped
        if (!running_.load(std::memory_order_acquire)) {
            break;
        }
    }
}

void AuditEmitter::shutdown() {
    // Idempotent: only shut down once
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
        return;
    }

    // Wake the writer thread so it exits its wait loop
    flush_cv_.notify_one();

    // Wait for writer thread to finish draining and exit
    if (writer_thread_.joinable()) {
        writer_thread_.join();
    }
}

AuditEmitter::Stats AuditEmitter::get_stats() const {
    return Stats{
        .total_emitted = total_emitted_.load(std::memory_order_relaxed),
        .total_written = total_written_.load(std::memory_order_relaxed),
        .overflow_dropped = ring_buffer_.overflow_count(),
        .flush_count = flush_count_.load(std::memory_order_relaxed)
    };
}

// ============================================================================
// Background Writer Thread
// ============================================================================

void AuditEmitter::writer_thread_func() {
    std::vector<AuditRecord> batch;
    batch.reserve(kMaxBatchSize);

    size_t batches_since_fsync = 0;

    while (true) {
        // Wait for: timeout, flush signal, or shutdown
        {
            std::unique_lock<std::mutex> lock(flush_mutex_);
            flush_cv_.wait_for(lock, batch_flush_interval_, [this] {
                return flush_requested_.load(std::memory_order_acquire)
                    || !running_.load(std::memory_order_acquire);
            });
        }

        // Drain the ring buffer in batches
        bool did_work = false;
        while (true) {
            batch.clear();
            size_t drained = ring_buffer_.drain(batch, kMaxBatchSize);

            if (drained == 0) {
                break;
            }

            did_work = true;

            // Build a single string for the entire batch to minimize
            // write() syscalls (one write per batch instead of per record)
            std::string output;
            output.reserve(drained * 512);  // Estimate ~512 bytes per JSON record

            for (const auto& record : batch) {
                output += to_json(record);
                output += '\n';
            }

            // Single write call for the entire batch
            file_stream_.write(output.data(), static_cast<std::streamsize>(output.size()));

            total_written_.fetch_add(drained, std::memory_order_relaxed);
            flush_count_.fetch_add(1, std::memory_order_relaxed);
            ++batches_since_fsync;

            // Periodic fsync to ensure durability without doing it every batch
            if (batches_since_fsync >= kFsyncInterval) {
                file_stream_.flush();
                batches_since_fsync = 0;
            }
        }

        // If a flush was explicitly requested, ensure data hits disk
        if (flush_requested_.load(std::memory_order_acquire)) {
            if (did_work) {
                file_stream_.flush();
                batches_since_fsync = 0;
            }
            // Signal flush() caller that we're done
            flush_requested_.store(false, std::memory_order_release);
        }

        // Check for shutdown after draining
        if (!running_.load(std::memory_order_acquire)) {
            // Final drain: get any records that arrived during shutdown
            batch.clear();
            while (ring_buffer_.drain(batch, kMaxBatchSize) > 0) {
                std::string output;
                output.reserve(batch.size() * 512);
                for (const auto& record : batch) {
                    output += to_json(record);
                    output += '\n';
                }
                file_stream_.write(output.data(), static_cast<std::streamsize>(output.size()));
                total_written_.fetch_add(batch.size(), std::memory_order_relaxed);
                flush_count_.fetch_add(1, std::memory_order_relaxed);
                batch.clear();
            }

            // Final flush and close
            file_stream_.flush();
            file_stream_.close();
            return;
        }
    }
}

// ============================================================================
// JSON Serialization (kept from original implementation)
// ============================================================================

std::string AuditEmitter::to_json(const AuditRecord& record) {
    std::ostringstream oss;
    oss << "{";

    // Event tracking - MUST BE FIRST for gap detection
    oss << "\"audit_id\":\"" << record.audit_id << "\",";
    oss << "\"sequence_num\":" << record.sequence_num << ",";

    // Timestamps - dual timestamp for queue time measurement
    oss << "\"timestamp\":\"" << utils::format_timestamp(record.timestamp) << "\",";
    oss << "\"received_at\":\"" << utils::format_timestamp(record.received_at) << "\",";

    // Request context
    oss << "\"user\":\"" << record.user << "\",";
    oss << "\"database\":\"" << record.database_name << "\",";
    if (!record.session_id.empty()) {
        oss << "\"session_id\":\"" << record.session_id << "\",";
    }
    if (!record.source_ip.empty()) {
        oss << "\"source_ip\":\"" << record.source_ip << "\",";
    }

    // SQL - escape quotes
    std::string escaped_sql = record.sql;
    size_t pos = 0;
    while ((pos = escaped_sql.find('"', pos)) != std::string::npos) {
        escaped_sql.replace(pos, 1, "\\\"");
        pos += 2;
    }
    oss << "\"sql\":\"" << escaped_sql << "\",";

    // Fingerprint for query shape grouping
    oss << "\"fingerprint_hash\":" << record.fingerprint.hash << ",";

    // Statement type
    oss << "\"statement_type\":\"" << statement_type_to_string(record.statement_type) << "\",";

    // Tables accessed
    oss << "\"tables\":[";
    for (size_t i = 0; i < record.tables.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << record.tables[i] << "\"";
    }
    oss << "],";

    // Columns filtered (WHERE/JOIN) - intent analysis
    oss << "\"columns_filtered\":[";
    for (size_t i = 0; i < record.columns_filtered.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << record.columns_filtered[i] << "\"";
    }
    oss << "],";

    // Policy decision with specificity
    oss << "\"decision\":\"" << decision_to_string(record.decision) << "\",";
    oss << "\"matched_policy\":\"" << record.matched_policy << "\",";
    oss << "\"rule_specificity\":" << record.rule_specificity << ",";
    if (!record.block_reason.empty()) {
        oss << "\"block_reason\":\"" << record.block_reason << "\",";
    }

    // Execution results
    oss << "\"execution_success\":" << (record.execution_success ? "true" : "false") << ",";
    oss << "\"error_code\":\"" << error_code_to_string(record.error_code) << "\",";

    if (record.execution_success) {
        oss << "\"rows_returned\":" << record.rows_returned << ",";
    }
    if (record.rows_affected > 0) {
        oss << "\"rows_affected\":" << record.rows_affected << ",";
    }

    // PII Classifications - compliance queries
    oss << "\"classifications\":[";
    for (size_t i = 0; i < record.detected_classifications.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << record.detected_classifications[i] << "\"";
    }
    oss << "],";
    oss << "\"has_pii\":" << (!record.detected_classifications.empty() ? "true" : "false") << ",";

    // Performance breakdown - separate proxy overhead from DB time
    oss << "\"total_duration_us\":" << record.total_duration.count() << ",";
    oss << "\"parse_time_us\":" << record.parse_time.count() << ",";
    oss << "\"policy_time_us\":" << record.policy_time.count() << ",";
    oss << "\"execution_time_us\":" << record.execution_time.count() << ",";
    oss << "\"classification_time_us\":" << record.classification_time.count() << ",";
    oss << "\"proxy_overhead_us\":" << record.proxy_overhead.count() << ",";

    // Operational flags
    oss << "\"rate_limited\":" << (record.rate_limited ? "true" : "false") << ",";
    oss << "\"cache_hit\":" << (record.cache_hit ? "true" : "false") << ",";
    oss << "\"circuit_breaker_tripped\":" << (record.circuit_breaker_tripped ? "true" : "false");

    oss << "}";

    return oss.str();
}

} // namespace sqlproxy
