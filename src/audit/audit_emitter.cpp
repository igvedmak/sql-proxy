#include "audit/audit_emitter.hpp"
#include "audit/file_sink.hpp"
#include "audit/webhook_sink.hpp"
#include "audit/syslog_sink.hpp"
#ifdef ENABLE_KAFKA
#include "audit/kafka_sink.hpp"
#endif
#include "core/utils.hpp"

#include <openssl/evp.h>

#include <format>
#include <future>
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

#ifdef ENABLE_KAFKA
    // Optional Kafka sink
    if (config.kafka_enabled && !config.kafka_brokers.empty()) {
        KafkaConfig kafka_cfg;
        kafka_cfg.brokers = config.kafka_brokers;
        kafka_cfg.topic = config.kafka_topic;
        auto kafka_sink = std::make_unique<KafkaSink>(kafka_cfg);
        if (kafka_sink->is_valid()) {
            sinks_.emplace_back(std::move(kafka_sink));
        } else {
            utils::log::error("Kafka sink: failed to initialize, skipping");
        }
    }
#endif

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
    if (sinks_.size() <= 1) {
        // Single sink: no parallelization overhead
        for (auto& sink : sinks_) {
            if (!sink->write(data)) {
                sink_write_failures_.fetch_add(1, std::memory_order_relaxed);
            }
        }
        return;
    }

    // Multiple sinks: write concurrently (e.g. file + webhook)
    // Each future writes to one sink; the data string_view remains valid
    // because we wait for all futures before returning.
    std::vector<std::future<bool>> futures;
    futures.reserve(sinks_.size());

    for (auto& sink : sinks_) {
        futures.push_back(std::async(std::launch::async,
            [&sink, data] { return sink->write(data); }));
    }

    for (auto& f : futures) {
        if (!f.get()) {
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
                const std::string json = to_json(record);
                output += (encryptor_ && encryptor_->is_enabled()) ? 
                    encryptor_->encrypt(json) : json;
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
// JSON Serialization — Section Builders
// ============================================================================

namespace {

void append_event_tracking(std::string& out, const AuditRecord& r) {
    out += std::format("\"audit_id\":\"{}\",\"sequence_num\":{},",
                       r.audit_id, r.sequence_num);
    if (!r.trace_id.empty()) {
        out += std::format("\"trace_id\":\"{}\",\"span_id\":\"{}\",\"parent_span_id\":\"{}\",",
                           r.trace_id, r.span_id, r.parent_span_id);
    }
    out += std::format("\"timestamp\":\"{}\",\"received_at\":\"{}\",",
                       utils::format_timestamp(r.timestamp),
                       utils::format_timestamp(r.received_at));
}

void append_request_context(std::string& out, const AuditRecord& r) {
    out += std::format("\"user\":\"{}\",\"database\":\"{}\",", r.user, r.database_name);
    if (!r.session_id.empty()) {
        out += std::format("\"session_id\":\"{}\",", r.session_id);
    }
    if (!r.source_ip.empty()) {
        out += std::format("\"source_ip\":\"{}\",", r.source_ip);
    }

    std::string escaped_sql;
    escaped_sql.reserve(r.sql.size());
    for (const char c : r.sql) {
        if (c == '"') escaped_sql += '\\';
        escaped_sql += c;
    }
    out += std::format("\"sql\":\"{}\",", escaped_sql);
    out += std::format("\"fingerprint_hash\":{},", r.fingerprint.hash);
    out += std::format("\"statement_type\":\"{}\",", statement_type_to_string(r.statement_type));
}

void append_string_array(std::string& out, std::string_view key,
                         const std::vector<std::string>& items) {
    out += '"';
    out += key;
    out += "\":[";
    for (size_t i = 0; i < items.size(); ++i) {
        if (i > 0) out += ',';
        out += std::format("\"{}\"", items[i]);
    }
    out += "],";
}

void append_policy_decision(std::string& out, const AuditRecord& r) {
    append_string_array(out, "tables", r.tables);
    append_string_array(out, "columns_filtered", r.columns_filtered);
    out += std::format("\"decision\":\"{}\",\"matched_policy\":\"{}\",\"rule_specificity\":{},",
                       decision_to_string(r.decision), r.matched_policy, r.rule_specificity);
    if (!r.block_reason.empty()) {
        out += std::format("\"block_reason\":\"{}\",", r.block_reason);
    }
}

void append_execution_results(std::string& out, const AuditRecord& r) {
    out += std::format("\"execution_success\":{},\"error_code\":\"{}\",",
                       utils::booltostr(r.execution_success),
                       error_code_to_string(r.error_code));
    if (r.execution_success) {
        out += std::format("\"rows_returned\":{},", r.rows_returned);
    }
    if (r.rows_affected > 0) {
        out += std::format("\"rows_affected\":{},", r.rows_affected);
    }
}

void append_classifications(std::string& out, const AuditRecord& r) {
    append_string_array(out, "classifications", r.detected_classifications);
    out += std::format("\"has_pii\":{},",
                       utils::booltostr(!r.detected_classifications.empty()));
}

void append_performance(std::string& out, const AuditRecord& r) {
    out += std::format(
        "\"total_duration_us\":{},\"parse_time_us\":{},\"policy_time_us\":{},"
        "\"execution_time_us\":{},\"classification_time_us\":{},\"proxy_overhead_us\":{},",
        r.total_duration.count(), r.parse_time.count(), r.policy_time.count(),
        r.execution_time.count(), r.classification_time.count(), r.proxy_overhead.count());
    if (r.query_cost > 0.0) {
        out += std::format("\"query_cost\":{:.2f},", r.query_cost);
    }
}

void append_operational(std::string& out, const AuditRecord& r) {
    out += std::format("\"rate_limited\":{},\"cache_hit\":{},\"circuit_breaker_tripped\":{},",
                       utils::booltostr(r.rate_limited),
                       utils::booltostr(r.cache_hit),
                       utils::booltostr(r.circuit_breaker_tripped));
    if (r.shadow_blocked) {
        out += std::format("\"shadow_blocked\":true,\"shadow_policy\":\"{}\",", r.shadow_policy);
    }
    if (!r.spans.empty()) {
        out += "\"spans\":[";
        for (size_t i = 0; i < r.spans.size(); ++i) {
            if (i > 0) out += ',';
            out += std::format("{{\"id\":\"{}\",\"op\":\"{}\",\"dur_us\":{}}}",
                               r.spans[i].span_id, r.spans[i].operation, r.spans[i].duration_us);
        }
        out += "],";
    }
    out += std::format("\"priority\":\"{}\",", priority_to_string(r.priority));
}

void append_integrity(std::string& out, const AuditRecord& r) {
    if (!r.record_hash.empty()) {
        out += std::format("\"record_hash\":\"{}\",\"previous_hash\":\"{}\"",
                           r.record_hash, r.previous_hash);
    } else {
        if (!out.empty() && out.back() == ',') out.pop_back();
    }
}

} // anonymous namespace

std::string AuditEmitter::to_json(const AuditRecord& record) {
    std::string result;
    result += '{';
    append_event_tracking(result, record);
    append_request_context(result, record);
    append_policy_decision(result, record);
    append_execution_results(result, record);
    append_classifications(result, record);
    append_performance(result, record);
    append_operational(result, record);
    append_integrity(result, record);
    result += '}';
    return result;
}

std::string AuditEmitter::compute_record_hash(
    const AuditRecord& record, const std::string& prev_hash) {

    // Hash: sequence_num|timestamp|user|sql|decision|previous_hash
    std::string input;
    input.reserve(256);
    input += std::format("{}", record.sequence_num);
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
