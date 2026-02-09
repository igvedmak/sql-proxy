#pragma once

#include "core/types.hpp"
#include "parser/fingerprinter.hpp"
#include <memory>
#include <mutex>
#include <unordered_map>
#include <list>
#include <optional>
#include <cstddef>
#include <atomic>

namespace sqlproxy {

/**
 * @brief Parsed query information stored in cache
 *
 * Contains both the parse result and analysis result to avoid
 * re-analyzing on cache hit.
 */
struct StatementInfo {
    QueryFingerprint fingerprint;
    ParsedQuery parsed;
    // AnalysisResult will be added when analyzer is implemented

    StatementInfo() = default;
    StatementInfo(QueryFingerprint fp, ParsedQuery pq)
        : fingerprint(std::move(fp)), parsed(std::move(pq)) {}
};

/**
 * @brief Sharded LRU cache for parsed SQL statements
 *
 * Performance characteristics:
 * - Cache hit:  ~500ns (fingerprint + shard lookup + strcmp for collision guard)
 * - Cache miss: ~50μs (parse with libpg_query)
 * - Expected hit rate: 80-95% for typical applications
 *
 * Sharding strategy:
 * - N shards = CPU cores (default: 16)
 * - Each shard has independent mutex → minimal contention
 * - Shard selected by hash % num_shards
 *
 * Collision safety:
 * - Store normalized query string alongside hash
 * - Compare strings on hash collision (~50ns strcmp)
 * - Hash collisions are extremely rare with xxHash64
 *
 * Thread-safety: Multiple threads can access different shards concurrently
 */
class ParseCache {
public:
    /**
     * @brief Construct cache with configuration
     * @param max_entries Total entries across all shards
     * @param num_shards Number of shards (default: 16)
     */
    explicit ParseCache(size_t max_entries = 10000, size_t num_shards = 16);

    ~ParseCache() = default;

    // Non-copyable, movable
    ParseCache(const ParseCache&) = delete;
    ParseCache& operator=(const ParseCache&) = delete;
    ParseCache(ParseCache&&) noexcept = default;
    ParseCache& operator=(ParseCache&&) noexcept = default;

    /**
     * @brief Lookup statement in cache
     * @param fingerprint Query fingerprint
     * @return Cached statement info, or nullopt on miss
     */
    std::optional<std::shared_ptr<StatementInfo>> get(const QueryFingerprint& fingerprint);

    /**
     * @brief Insert statement into cache
     * @param info Statement info to cache
     */
    void put(std::shared_ptr<StatementInfo> info);

    /**
     * @brief Clear entire cache
     */
    void clear();

    /**
     * @brief Get cache statistics
     */
    struct Stats {
        size_t total_entries;
        size_t hits;
        size_t misses;
        size_t evictions;
        size_t ddl_invalidations;

        double hit_rate() const {
            size_t total = hits + misses;
            return total > 0 ? static_cast<double>(hits) / total : 0.0;
        }
    };

    Stats get_stats() const;

    /**
     * @brief Invalidate all cache entries referencing a table
     * @param table_name Table name to invalidate
     * @return Number of entries invalidated
     */
    size_t invalidate_table(const std::string& table_name);

private:
    /**
     * @brief Single shard with LRU eviction
     */
    class Shard {
    public:
        explicit Shard(size_t max_entries);

        // Non-copyable, non-movable (due to mutex)
        Shard(const Shard&) = delete;
        Shard& operator=(const Shard&) = delete;
        Shard(Shard&&) = delete;
        Shard& operator=(Shard&&) = delete;

        std::optional<std::shared_ptr<StatementInfo>> get(const QueryFingerprint& fingerprint);
        void put(std::shared_ptr<StatementInfo> info);
        void clear();
        size_t invalidate_table(const std::string& table_name);

        size_t size() const;
        size_t eviction_count() const { return evictions_; }

    private:
        using LRUList = std::list<std::shared_ptr<StatementInfo>>;
        using CacheMap = std::unordered_map<uint64_t, LRUList::iterator>;

        void evict_lru();

        mutable std::mutex mutex_;
        size_t max_entries_;
        size_t evictions_;

        LRUList lru_list_;          // Most recently used at front
        CacheMap cache_map_;         // hash -> iterator in lru_list
    };

    /**
     * @brief Select shard for hash
     */
    size_t select_shard(uint64_t hash) const {
        return hash % shards_.size();
    }

    std::vector<std::unique_ptr<Shard>> shards_;

    // Statistics (atomic for thread-safety)
    mutable std::atomic<uint64_t> hits_;
    mutable std::atomic<uint64_t> misses_;
    std::atomic<uint64_t> ddl_invalidations_{0};
};

} // namespace sqlproxy
