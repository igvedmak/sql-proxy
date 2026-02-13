#pragma once

#include "core/types.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace sqlproxy {

class ResultCache {
public:
    struct Config {
        bool enabled = false;
        size_t max_entries = 5000;
        size_t num_shards = 16;
        std::chrono::seconds ttl{60};
        size_t max_result_size_bytes = 1048576;  // 1MB
    };

    explicit ResultCache(const Config& config);

    /// Lookup cached result. Returns nullopt on miss or expiry.
    [[nodiscard]] std::optional<QueryResult> get(
        uint64_t fingerprint_hash, const std::string& user,
        const std::string& database);

    /// Insert result into cache (only for SELECT, size checked).
    void put(uint64_t fingerprint_hash, const std::string& user,
             const std::string& database, const QueryResult& result,
             std::vector<std::string> tables = {});

    /// Invalidate all entries matching a database (called on writes).
    void invalidate(const std::string& database);

    /// Invalidate entries that reference any of the given tables.
    void invalidate_tables(const std::vector<std::string>& tables);

    [[nodiscard]] bool is_enabled() const { return config_.enabled; }

    struct Stats {
        uint64_t hits;
        uint64_t misses;
        uint64_t evictions;
        uint64_t invalidations;
        size_t current_entries;
    };
    [[nodiscard]] Stats get_stats() const;

private:
    struct CacheEntry {
        std::string key;
        std::string database;                // For database-level invalidation
        std::vector<std::string> tables;     // For table-level invalidation
        QueryResult result;
        std::chrono::steady_clock::time_point expires_at;
        uint64_t db_generation = 0;          // Generation at insert time (for O(1) invalidation)
    };

    class Shard {
    public:
        explicit Shard(size_t max_entries) : max_entries_(max_entries) {}

        std::optional<QueryResult> get(const std::string& key);
        void put(const std::string& key, const std::string& database,
                 std::vector<std::string> tables, QueryResult result,
                 std::chrono::steady_clock::time_point expires_at);
        size_t invalidate(const std::string& database);
        size_t invalidate_tables(const std::vector<std::string>& tables);
        size_t size() const;

        std::atomic<uint64_t> evictions{0};

    private:
        mutable std::mutex mutex_;
        size_t max_entries_;
        std::list<CacheEntry> lru_list_;
        std::unordered_map<std::string, std::list<CacheEntry>::iterator> map_;
        std::unordered_map<std::string, uint64_t> db_generations_;  // For O(1) invalidation
    };

    static std::string make_key(uint64_t hash, const std::string& user,
                                const std::string& db);
    size_t select_shard(const std::string& key) const;
    size_t estimate_result_size(const QueryResult& result) const;

    Config config_;
    std::vector<std::unique_ptr<Shard>> shards_;
    std::atomic<uint64_t> hits_{0};
    std::atomic<uint64_t> misses_{0};
    std::atomic<uint64_t> invalidations_{0};
};

} // namespace sqlproxy
