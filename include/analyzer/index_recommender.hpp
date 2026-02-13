#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace sqlproxy {

struct AnalysisResult;  // forward declare

class IndexRecommender {
public:
    struct Config {
        bool enabled = false;
        uint32_t min_occurrences = 3;
        size_t max_recommendations = 50;
    };

    struct Recommendation {
        std::string table;
        std::vector<std::string> columns;
        std::string reason;
        uint32_t occurrence_count;
        double avg_execution_time_us;
        std::string suggested_ddl;
    };

    IndexRecommender();
    explicit IndexRecommender(Config config);

    void record(const AnalysisResult& analysis, uint64_t fingerprint,
                std::chrono::microseconds exec_time);

    [[nodiscard]] std::vector<Recommendation> get_recommendations() const;
    [[nodiscard]] bool is_enabled() const { return config_.enabled; }

private:
    struct FilterPattern {
        std::string table;
        std::vector<std::string> columns;
        std::atomic<uint32_t> count{0};       // Lock-free update under shared_lock
        std::atomic<int64_t> total_time_us{0}; // Lock-free update under shared_lock
    };

    Config config_;
    // key: "table:col1,col2" -> FilterPattern (shared_ptr for lock-free counter updates)
    std::unordered_map<std::string, std::shared_ptr<FilterPattern>> patterns_;
    mutable std::shared_mutex mutex_;
};

} // namespace sqlproxy
