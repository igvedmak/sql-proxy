#include "cache/result_cache.hpp"

#include <format>
#include <functional>

namespace sqlproxy {

// ============================================================================
// ResultCache
// ============================================================================

ResultCache::ResultCache(const Config& config)
    : config_(config) {
    const size_t num_shards = std::max(config_.num_shards, size_t{1});
    const size_t per_shard = std::max(config_.max_entries / num_shards, size_t{1});
    shards_.reserve(num_shards);
    for (size_t i = 0; i < num_shards; ++i) {
        shards_.push_back(std::make_unique<Shard>(per_shard));
    }
}

std::string ResultCache::make_key(uint64_t hash, const std::string& user,
                                  const std::string& db) {
    return std::format("{}:{}:{}", hash, user, db);
}

size_t ResultCache::select_shard(const std::string& key) const {
    return std::hash<std::string>{}(key) % shards_.size();
}

size_t ResultCache::estimate_result_size(const QueryResult& result) const {
    size_t size = 0;
    for (const auto& col : result.column_names) {
        size += col.size();
    }
    for (const auto& row : result.rows) {
        for (const auto& cell : row) {
            size += cell.size();
        }
    }
    return size;
}

std::optional<QueryResult> ResultCache::get(
    uint64_t fingerprint_hash, const std::string& user,
    const std::string& database) {
    const auto key = make_key(fingerprint_hash, user, database);
    auto& shard = *shards_[select_shard(key)];
    const auto result = shard.get(key);
    if (result) {
        hits_.fetch_add(1, std::memory_order_relaxed);
    } else {
        misses_.fetch_add(1, std::memory_order_relaxed);
    }
    return result;
}

void ResultCache::put(uint64_t fingerprint_hash, const std::string& user,
                      const std::string& database, const QueryResult& result,
                      std::vector<std::string> tables) {
    // Skip oversized results
    if (estimate_result_size(result) > config_.max_result_size_bytes) {
        return;
    }

    const auto key = make_key(fingerprint_hash, user, database);
    const auto expires = std::chrono::steady_clock::now() + config_.ttl;
    auto& shard = *shards_[select_shard(key)];
    shard.put(key, database, std::move(tables), result, expires);
}

void ResultCache::invalidate(const std::string& database) {
    for (auto& shard : shards_) {
        shard->invalidate(database);
    }
    invalidations_.fetch_add(1, std::memory_order_relaxed);
}

void ResultCache::invalidate_tables(const std::vector<std::string>& tables) {
    if (tables.empty()) return;
    for (auto& shard : shards_) {
        shard->invalidate_tables(tables);
    }
    invalidations_.fetch_add(1, std::memory_order_relaxed);
}

ResultCache::Stats ResultCache::get_stats() const {
    size_t entries = 0;
    uint64_t evictions = 0;
    for (const auto& shard : shards_) {
        entries += shard->size();
        evictions += shard->evictions.load(std::memory_order_relaxed);
    }
    return {
        .hits = hits_.load(std::memory_order_relaxed),
        .misses = misses_.load(std::memory_order_relaxed),
        .evictions = evictions,
        .invalidations = invalidations_.load(std::memory_order_relaxed),
        .current_entries = entries,
    };
}

// ============================================================================
// Shard
// ============================================================================

std::optional<QueryResult> ResultCache::Shard::get(const std::string& key) {
    std::lock_guard lock(mutex_);
    auto it = map_.find(key);
    if (it == map_.end()) return std::nullopt;

    auto& entry = *it->second;

    // Generation check: entry is stale if database was invalidated after insertion
    auto gen_it = db_generations_.find(entry.database);
    if (gen_it != db_generations_.end() && entry.db_generation < gen_it->second) {
        lru_list_.erase(it->second);
        map_.erase(it);
        return std::nullopt;
    }

    // TTL check
    if (std::chrono::steady_clock::now() >= entry.expires_at) {
        lru_list_.erase(it->second);
        map_.erase(it);
        return std::nullopt;
    }

    // Move to front (most recently used)
    lru_list_.splice(lru_list_.begin(), lru_list_, it->second);
    return entry.result;
}

void ResultCache::Shard::put(
    const std::string& key, const std::string& database,
    std::vector<std::string> tables, QueryResult result,
    std::chrono::steady_clock::time_point expires_at) {
    std::lock_guard lock(mutex_);

    // If key exists, update it
    auto it = map_.find(key);
    if (it != map_.end()) {
        uint64_t gen = 0;
        auto gen_it = db_generations_.find(database);
        if (gen_it != db_generations_.end()) gen = gen_it->second;
        it->second->tables = std::move(tables);
        it->second->result = std::move(result);
        it->second->expires_at = expires_at;
        it->second->db_generation = gen;
        lru_list_.splice(lru_list_.begin(), lru_list_, it->second);
        return;
    }

    // Evict LRU if at capacity
    while (map_.size() >= max_entries_ && !lru_list_.empty()) {
        auto& back = lru_list_.back();
        map_.erase(back.key);
        lru_list_.pop_back();
        evictions.fetch_add(1, std::memory_order_relaxed);
    }

    // Insert new entry at front with current database generation
    uint64_t gen = 0;
    auto gen_it = db_generations_.find(database);
    if (gen_it != db_generations_.end()) gen = gen_it->second;
    lru_list_.emplace_front(CacheEntry{key, database, std::move(tables), std::move(result), expires_at, gen});
    map_[key] = lru_list_.begin();
}

size_t ResultCache::Shard::invalidate(const std::string& database) {
    std::lock_guard lock(mutex_);
    // O(1) generation bump — stale entries are lazily evicted on get()
    db_generations_[database]++;
    return 0;  // Actual removal happens lazily
}

size_t ResultCache::Shard::invalidate_tables(const std::vector<std::string>& tables) {
    std::lock_guard lock(mutex_);
    size_t removed = 0;
    for (auto it = lru_list_.begin(); it != lru_list_.end(); ) {
        bool hit = false;
        for (const auto& cached_table : it->tables) {
            for (const auto& target : tables) {
                if (cached_table == target) {
                    hit = true;
                    break;
                }
            }
            if (hit) break;
        }
        if (hit) {
            map_.erase(it->key);
            it = lru_list_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    return removed;
}

size_t ResultCache::Shard::size() const {
    std::lock_guard lock(mutex_);
    return map_.size();
}

} // namespace sqlproxy
