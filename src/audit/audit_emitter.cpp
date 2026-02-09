#include "audit/audit_emitter.hpp"
#include "audit/file_sink.hpp"
#include "audit/webhook_sink.hpp"
#include "audit/syslog_sink.hpp"
#include "core/utils.hpp"

#include <openssl/evp.h>

#include <format>
#include <thread>

namespace sqlproxy {

// ============================================================================
// Construction / Destruction
// ============================================================================

AuditEmitter::AuditEmitter(const AuditConfig& config)
    : batch_flush_interval_(config.batch_flush_interval),
      integrity_enabled_(config.integrity_enabled) {

    // Always create a FileSink with rotation settings
    FileSink::Config file_cfg;
    file_cfg.output_file = config.output_file;
    file_cfg.max_file_size_bytes = config.rotation_max_file_size_mb * 1024ULL * 1024;
    file_cfg.max_files = config.rotation_max_files;
    file_cfg.rotation_interval = std::chrono::hours(config.rotation_interval_hours);
    file_cfg.time_based_rotation = config.rotation_time_based;
    file_cfg.size_based_rotation = config.rotation_size_based;
    sinks_.push_back(std::make_unique<FileSink>(file_cfg));

    // Optional webhook sink
    if (config.webhook_enabled && !config.webhook_url.empty()) {
        WebhookSink::Config wh_cfg;
        wh_cfg.url = config.webhook_url;
        wh_cfg.auth_header = config.webhook_auth_header;
        wh_cfg.timeout = std::chrono::milliseconds(config.webhook_timeout_ms);
        wh_cfg.max_retries = config.webhook_max_retries;
        wh_cfg.batch_size = static_cast<size_t>(config.webhook_batch_size);
        sinks_.push_back(std::make_unique<WebhookSink>(wh_cfg));
    }

    // Optional syslog sink
    if (config.syslog_enabled) {
        SyslogSink::Config sl_cfg;
        sl_cfg.ident = config.syslog_ident;
        sinks_.push_back(std::make_unique<SyslogSink>(sl_cfg));
    }

    start();
}

AuditEmitter::AuditEmitter(std::string output_file)
    : batch_flush_interval_(100) {
    FileSink::Config file_cfg;
    file_cfg.output_file = std::move(output_file);
    sinks_.push_back(std::make_unique<FileSink>(file_cfg));
    start();
}

void AuditEmitter::start() {
    running_.store(true, std::memory_order_release);
    writer_thread_ = std::thread(&AuditEmitter::writer_thread_func, this);
}

AuditEmitter::~AuditEmitter() {
    shutdown();
}

// ============================================================================
// Public Interface
// ============================================================================

void AuditEmitter::emit(AuditRecord record) {
    if (!running_.load(std::memory_order_acquire)) {
        return;
    }

    record.sequence_num = sequence_counter_.fetch_add(1, std::memory_order_relaxed);
    (void)ring_buffer_.try_push(std::move(record));
    total_emitted_.fetch_add(1, std::memory_order_relaxed);
}

void AuditEmitter::flush() {
    if (!running_.load(std::memory_order_acquire)) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(flush_mutex_);
        flush_requested_.store(true, std::memory_order_release);
    }
    flush_cv_.notify_one();

    while (flush_requested_.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        if (!running_.load(std::memory_order_acquire)) {
            break;
        }
    }
}

void AuditEmitter::shutdown() {
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
        return;
    }

    flush_cv_.notify_one();

    if (writer_thread_.joinable()) {
        writer_thread_.join();
    }
}

AuditEmitter::Stats AuditEmitter::get_stats() const {
    return Stats{
        .total_emitted = total_emitted_.load(std::memory_order_relaxed),
        .total_written = total_written_.load(std::memory_order_relaxed),
        .overflow_dropped = ring_buffer_.overflow_count(),
        .flush_count = flush_count_.load(std::memory_order_relaxed),
        .sink_write_failures = sink_write_failures_.load(std::memory_order_relaxed),
        .active_sinks = sinks_.size()
    };
}

// ============================================================================
// Sink Helpers
// ============================================================================

void AuditEmitter::write_to_sinks(std::string_view data) {
    for (auto& sink : sinks_) {
        if (!sink->write(data)) {
            sink_write_failures_.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

void AuditEmitter::flush_sinks() {
    for (auto& sink : sinks_) {
        sink->flush();
    }
}

void AuditEmitter::shutdown_sinks() {
    for (auto& sink : sinks_) {
        sink->flush();
        sink->shutdown();
    }
}

// ============================================================================
// Background Writer Thread
// ============================================================================

void AuditEmitter::writer_thread_func() {
    std::vector<AuditRecord> batch;
    batch.reserve(kMaxBatchSize);

    size_t batches_since_fsync = 0;

    while (true) {
        {
            std::unique_lock<std::mutex> lock(flush_mutex_);
            flush_cv_.wait_for(lock, batch_flush_interval_, [this] {
                return flush_requested_.load(std::memory_order_acquire)
                    || !running_.load(std::memory_order_acquire);
            });
        }

        bool did_work = false;
        while (true) {
            batch.clear();
            size_t drained = ring_buffer_.drain(batch, kMaxBatchSize);

            if (drained == 0) {
                break;
            }

            did_work = true;

            // Compute hash chain (single-threaded, safe without locks)
            if (integrity_enabled_) {
                for (auto& record : batch) {
                    record.previous_hash = previous_hash_;
                    record.record_hash = compute_record_hash(record, previous_hash_);
                    previous_hash_ = record.record_hash;
                }
            }

            // Build a single string for the entire batch
            std::string output;
            output.reserve(drained * 512);

            for (const auto& record : batch) {
                output += to_json(record);
                output += '\n';
            }

            // Write to all sinks
            write_to_sinks(output);

            total_written_.fetch_add(drained, std::memory_order_relaxed);
            flush_count_.fetch_add(1, std::memory_order_relaxed);
            ++batches_since_fsync;

            if (batches_since_fsync >= kFsyncInterval) {
                flush_sinks();
                batches_since_fsync = 0;
            }
        }

        if (flush_requested_.load(std::memory_order_acquire)) {
            if (did_work) {
                flush_sinks();
                batches_since_fsync = 0;
            }
            flush_requested_.store(false, std::memory_order_release);
        }

        if (!running_.load(std::memory_order_acquire)) {
            // Final drain
            batch.clear();
            while (ring_buffer_.drain(batch, kMaxBatchSize) > 0) {
                std::string output;
                output.reserve(batch.size() * 512);
                for (const auto& record : batch) {
                    output += to_json(record);
                    output += '\n';
                }
                write_to_sinks(output);
                total_written_.fetch_add(batch.size(), std::memory_order_relaxed);
                flush_count_.fetch_add(1, std::memory_order_relaxed);
                batch.clear();
            }

            shutdown_sinks();
            return;
        }
    }
}

// ============================================================================
// JSON Serialization
// ============================================================================

std::string AuditEmitter::to_json(const AuditRecord& record) {
    std::string result;
    result += "{";

    // Event tracking
    result += std::format("\"audit_id\":\"{}\",\"sequence_num\":{},",
                          record.audit_id, record.sequence_num);

    // Distributed tracing
    if (!record.trace_id.empty()) {
        result += std::format("\"trace_id\":\"{}\",\"span_id\":\"{}\",\"parent_span_id\":\"{}\",",
                              record.trace_id, record.span_id, record.parent_span_id);
    }

    // Timestamps
    result += std::format("\"timestamp\":\"{}\",\"received_at\":\"{}\",",
                          utils::format_timestamp(record.timestamp),
                          utils::format_timestamp(record.received_at));

    // Request context
    result += std::format("\"user\":\"{}\",\"database\":\"{}\",",
                          record.user, record.database_name);
    if (!record.session_id.empty()) {
        result += std::format("\"session_id\":\"{}\",", record.session_id);
    }
    if (!record.source_ip.empty()) {
        result += std::format("\"source_ip\":\"{}\",", record.source_ip);
    }

    // SQL
    std::string escaped_sql;
    escaped_sql.reserve(record.sql.size());
    for (const char c : record.sql) {
        if (c == '"') escaped_sql += '\\';
        escaped_sql += c;
    }
    result += std::format("\"sql\":\"{}\",", escaped_sql);

    // Fingerprint
    result += std::format("\"fingerprint_hash\":{},", record.fingerprint.hash);

    // Statement type
    result += std::format("\"statement_type\":\"{}\",", statement_type_to_string(record.statement_type));

    // Tables
    result += "\"tables\":[";
    for (size_t i = 0; i < record.tables.size(); ++i) {
        if (i > 0) result += ",";
        result += std::format("\"{}\"", record.tables[i]);
    }
    result += "],";

    // Columns filtered
    result += "\"columns_filtered\":[";
    for (size_t i = 0; i < record.columns_filtered.size(); ++i) {
        if (i > 0) result += ",";
        result += std::format("\"{}\"", record.columns_filtered[i]);
    }
    result += "],";

    // Policy decision
    result += std::format("\"decision\":\"{}\",\"matched_policy\":\"{}\",\"rule_specificity\":{},",
                          decision_to_string(record.decision),
                          record.matched_policy,
                          record.rule_specificity);
    if (!record.block_reason.empty()) {
        result += std::format("\"block_reason\":\"{}\",", record.block_reason);
    }

    // Execution results
    result += std::format("\"execution_success\":{},\"error_code\":\"{}\",",
                          record.execution_success ? "true" : "false",
                          error_code_to_string(record.error_code));

    if (record.execution_success) {
        result += std::format("\"rows_returned\":{},", record.rows_returned);
    }
    if (record.rows_affected > 0) {
        result += std::format("\"rows_affected\":{},", record.rows_affected);
    }

    // PII Classifications
    result += "\"classifications\":[";
    for (size_t i = 0; i < record.detected_classifications.size(); ++i) {
        if (i > 0) result += ",";
        result += std::format("\"{}\"", record.detected_classifications[i]);
    }
    result += std::format("],\"has_pii\":{},",
                          !record.detected_classifications.empty() ? "true" : "false");

    // Performance
    result += std::format("\"total_duration_us\":{},\"parse_time_us\":{},\"policy_time_us\":{},\"execution_time_us\":{},\"classification_time_us\":{},\"proxy_overhead_us\":{},",
                          record.total_duration.count(),
                          record.parse_time.count(),
                          record.policy_time.count(),
                          record.execution_time.count(),
                          record.classification_time.count(),
                          record.proxy_overhead.count());

    // Operational flags
    result += std::format("\"rate_limited\":{},\"cache_hit\":{},\"circuit_breaker_tripped\":{},",
                          record.rate_limited ? "true" : "false",
                          record.cache_hit ? "true" : "false",
                          record.circuit_breaker_tripped ? "true" : "false");

    // Shadow mode
    if (record.shadow_blocked) {
        result += std::format("\"shadow_blocked\":true,\"shadow_policy\":\"{}\",",
                              record.shadow_policy);
    }

    // Integrity (hash chain)
    if (!record.record_hash.empty()) {
        result += std::format("\"record_hash\":\"{}\",\"previous_hash\":\"{}\"",
                              record.record_hash, record.previous_hash);
    } else {
        // Remove trailing comma
        if (!result.empty() && result.back() == ',') {
            result.pop_back();
        }
    }

    result += "}";
    return result;
}

std::string AuditEmitter::compute_record_hash(
    const AuditRecord& record, const std::string& prev_hash) {

    // Hash: sequence_num|timestamp|user|sql|decision|previous_hash
    std::string input;
    input.reserve(256);
    input += std::to_string(record.sequence_num);
    input += '|';
    input += utils::format_timestamp(record.timestamp);
    input += '|';
    input += record.user;
    input += '|';
    input += record.sql;
    input += '|';
    input += decision_to_string(record.decision);
    input += '|';
    input += prev_hash;

    // SHA-256 via OpenSSL EVP
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, input.data(), input.size());
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    // Convert to hex string
    static constexpr char hex_chars[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(hash_len * 2);
    for (unsigned int i = 0; i < hash_len; ++i) {
        hex += hex_chars[(hash[i] >> 4) & 0x0F];
        hex += hex_chars[hash[i] & 0x0F];
    }
    return hex;
}

} // namespace sqlproxy
