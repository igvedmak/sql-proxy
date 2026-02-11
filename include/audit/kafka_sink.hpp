#pragma once

#ifdef ENABLE_KAFKA

#include "audit/audit_sink.hpp"
#include <string>
#include <atomic>

// Forward-declare librdkafka types
typedef struct rd_kafka_s rd_kafka_t;
typedef struct rd_kafka_topic_s rd_kafka_topic_t;

namespace sqlproxy {

struct KafkaConfig {
    std::string brokers = "localhost:9092";
    std::string topic = "sql-proxy-audit";
    int queue_buffering_max_ms = 500;
    int batch_num_messages = 1000;
    std::string compression_codec = "snappy";  // none, gzip, snappy, lz4, zstd
};

/**
 * @brief Kafka audit sink using librdkafka
 *
 * Produces audit JSON records to a Kafka topic.
 * Uses asynchronous delivery with internal buffering.
 */
class KafkaSink : public IAuditSink {
public:
    explicit KafkaSink(const KafkaConfig& config);
    ~KafkaSink() override;

    // Non-copyable
    KafkaSink(const KafkaSink&) = delete;
    KafkaSink& operator=(const KafkaSink&) = delete;

    [[nodiscard]] bool write(std::string_view json_line) override;
    void flush() override;
    void shutdown() override;
    [[nodiscard]] std::string name() const override;

    [[nodiscard]] bool is_valid() const { return producer_ != nullptr; }
    [[nodiscard]] uint64_t messages_produced() const {
        return messages_produced_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] uint64_t delivery_errors() const {
        return delivery_errors_.load(std::memory_order_relaxed);
    }

private:
    static void delivery_callback(rd_kafka_t* rk, const void* payload, size_t len,
                                   int error_code, void* opaque, void* msg_opaque);

    KafkaConfig config_;
    rd_kafka_t* producer_ = nullptr;
    rd_kafka_topic_t* topic_ = nullptr;
    std::atomic<uint64_t> messages_produced_{0};
    std::atomic<uint64_t> delivery_errors_{0};
};

} // namespace sqlproxy

#endif // ENABLE_KAFKA
