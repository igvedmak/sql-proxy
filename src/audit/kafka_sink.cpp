#ifdef ENABLE_KAFKA

#include "audit/kafka_sink.hpp"
#include "core/utils.hpp"

#include <librdkafka/rdkafka.h>
#include <format>
#include <cstring>

namespace sqlproxy {

void KafkaSink::delivery_callback(rd_kafka_t* /*rk*/, const void* /*payload*/, size_t /*len*/,
                                   int error_code, void* opaque, void* /*msg_opaque*/) {
    auto* self = static_cast<KafkaSink*>(opaque);
    if (error_code != 0) {
        self->delivery_errors_.fetch_add(1, std::memory_order_relaxed);
    }
}

KafkaSink::KafkaSink(const KafkaConfig& config)
    : config_(config) {

    char errstr[512];
    rd_kafka_conf_t* conf = rd_kafka_conf_new();

    // Set broker list
    if (rd_kafka_conf_set(conf, "bootstrap.servers", config_.brokers.c_str(),
                          errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
        utils::log::error(std::format("Kafka: failed to set brokers: {}", errstr));
        rd_kafka_conf_destroy(conf);
        return;
    }

    // Batching and performance
    rd_kafka_conf_set(conf, "queue.buffering.max.ms",
                      std::to_string(config_.queue_buffering_max_ms).c_str(),
                      errstr, sizeof(errstr));
    rd_kafka_conf_set(conf, "batch.num.messages",
                      std::to_string(config_.batch_num_messages).c_str(),
                      errstr, sizeof(errstr));
    rd_kafka_conf_set(conf, "compression.codec",
                      config_.compression_codec.c_str(),
                      errstr, sizeof(errstr));

    // Delivery callback
    rd_kafka_conf_set_dr_cb(conf, delivery_callback);
    rd_kafka_conf_set_opaque(conf, this);

    // Create producer
    producer_ = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
    if (!producer_) {
        utils::log::error(std::format("Kafka: failed to create producer: {}", errstr));
        // conf is freed by rd_kafka_new on failure
        return;
    }
    // conf ownership transferred to producer_

    // Create topic handle
    topic_ = rd_kafka_topic_new(producer_, config_.topic.c_str(), nullptr);
    if (!topic_) {
        utils::log::error(std::format("Kafka: failed to create topic '{}'", config_.topic));
        rd_kafka_destroy(producer_);
        producer_ = nullptr;
        return;
    }

    utils::log::info(std::format("Kafka sink: connected to {} (topic={})",
        config_.brokers, config_.topic));
}

KafkaSink::~KafkaSink() {
    shutdown();
}

bool KafkaSink::write(std::string_view json_line) {
    if (!producer_ || !topic_) return false;

    const int result = rd_kafka_produce(
        topic_,
        RD_KAFKA_PARTITION_UA,          // Auto-partition
        RD_KAFKA_MSG_F_COPY,            // Copy payload
        const_cast<char*>(json_line.data()),
        json_line.size(),
        nullptr, 0,                      // No key
        nullptr                          // No opaque
    );

    if (result == -1) {
        const auto err = rd_kafka_last_error();
        if (err == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
            // Backpressure: poll to drain delivery reports and retry
            rd_kafka_poll(producer_, 100);
            // One retry
            if (rd_kafka_produce(topic_, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY,
                                  const_cast<char*>(json_line.data()), json_line.size(),
                                  nullptr, 0, nullptr) == -1) {
                delivery_errors_.fetch_add(1, std::memory_order_relaxed);
                return false;
            }
        } else {
            delivery_errors_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
    }

    messages_produced_.fetch_add(1, std::memory_order_relaxed);

    // Poll for delivery callbacks (non-blocking)
    rd_kafka_poll(producer_, 0);
    return true;
}

void KafkaSink::flush() {
    if (!producer_) return;
    rd_kafka_flush(producer_, 5000);  // 5s timeout
}

void KafkaSink::shutdown() {
    if (topic_) {
        rd_kafka_topic_destroy(topic_);
        topic_ = nullptr;
    }
    if (producer_) {
        rd_kafka_flush(producer_, 10000);  // 10s final flush
        rd_kafka_destroy(producer_);
        producer_ = nullptr;
    }
}

std::string KafkaSink::name() const {
    return std::format("kafka:{}:{}", config_.brokers, config_.topic);
}

} // namespace sqlproxy

#endif // ENABLE_KAFKA
