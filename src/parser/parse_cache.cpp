#include "parser/parse_cache.hpp"
#include <algorithm>

namespace sqlproxy {

// ============================================================================
// ParseCache Implementation
// ============================================================================

ParseCache::ParseCache(size_t max_entries, size_t num_shards)
    : hits_(0), misses_(0) {

    if (num_shards == 0) {
        num_shards = 16; // Default
    }

    // Distribute entries evenly across shards
    const size_t entries_per_shard = std::max<size_t>(1, max_entries / num_shards);

    // Use unique_ptr since Shard is not movable (contains mutex)
    for (size_t i = 0; i < num_shards; ++i) {
        shards_.push_back(std::make_unique<Shard>(entries_per_shard));
    }
}

std::optional<std::shared_ptr<StatementInfo>> ParseCache::get(const QueryFingerprint& fingerprint) {
    const size_t shard_idx = select_shard(fingerprint.hash);
    const auto result = shards_[shard_idx]->get(fingerprint);

    if (result.has_value()) {
        hits_.fetch_add(1, std::memory_order_relaxed);
    } else {
        misses_.fetch_add(1, std::memory_order_relaxed);
    }

    return result;
}

void ParseCache::put(std::shared_ptr<StatementInfo> info) {
    const size_t shard_idx = select_shard(info->fingerprint.hash);
    shards_[shard_idx]->put(std::move(info));
}

void ParseCache::clear() {
    for (auto& shard : shards_) {
        shard->clear();
    }
    hits_.store(0, std::memory_order_relaxed);
    misses_.store(0, std::memory_order_relaxed);
}

ParseCache::Stats ParseCache::get_stats() const {
    Stats stats;

    // Aggregate from all shards
    size_t total_entries = 0;
    size_t total_evictions = 0;

    for (const auto& shard : shards_) {
        total_entries += shard->size();
        total_evictions += shard->eviction_count();
    }

    stats.total_entries = total_entries;
    stats.hits = hits_.load(std::memory_order_relaxed);
    stats.misses = misses_.load(std::memory_order_relaxed);
    stats.evictions = total_evictions;
    stats.ddl_invalidations = ddl_invalidations_.load(std::memory_order_relaxed);

    return stats;
}

size_t ParseCache::invalidate_table(const std::string& table_name) {
    size_t total = 0;
    for (auto& shard : shards_) {
        total += shard->invalidate_table(table_name);
    }
    if (total > 0) {
        ddl_invalidations_.fetch_add(total, std::memory_order_relaxed);
    }
    return total;
}

// ============================================================================
// Shard Implementation
// ============================================================================

ParseCache::Shard::Shard(size_t max_entries)
    : max_entries_(max_entries), evictions_(0) {
    // Pre-allocate to reduce allocations during runtime
    cache_map_.reserve(max_entries);
}

std::optional<std::shared_ptr<StatementInfo>> ParseCache::Shard::get(
    const QueryFingerprint& fingerprint) {

    std::lock_guard<std::mutex> lock(mutex_);

    const auto it = cache_map_.find(fingerprint.hash);
    if (it == cache_map_.end()) {
        return std::nullopt;
    }

    // Collision guard: verify normalized query matches
    auto& cached_info = *(it->second);
    if (cached_info->fingerprint.normalized != fingerprint.normalized) {
        // Hash collision (extremely rare) - treat as miss
        return std::nullopt;
    }

    // Move to front (most recently used)
    lru_list_.splice(lru_list_.begin(), lru_list_, it->second);

    return *it->second;
}

void ParseCache::Shard::put(std::shared_ptr<StatementInfo> info) {
    std::lock_guard<std::mutex> lock(mutex_);

    const uint64_t hash = info->fingerprint.hash;

    // Check if already exists
    const auto it = cache_map_.find(hash);
    if (it != cache_map_.end()) {
        // Update existing entry and move to front
        *(it->second) = info;
        lru_list_.splice(lru_list_.begin(), lru_list_, it->second);
        return;
    }

    // Evict if at capacity
    if (lru_list_.size() >= max_entries_) {
        evict_lru();
    }

    // Insert new entry at front
    lru_list_.push_front(std::move(info));
    cache_map_[hash] = lru_list_.begin();
}

void ParseCache::Shard::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    lru_list_.clear();
    cache_map_.clear();
}

size_t ParseCache::Shard::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return lru_list_.size();
}

size_t ParseCache::Shard::invalidate_table(const std::string& table_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;

    for (auto it = lru_list_.begin(); it != lru_list_.end(); ) {
        bool references_table = false;
        const auto& tables = (*it)->parsed.tables;
        for (const auto& tref : tables) {
            // Case-insensitive comparison
            if (tref.table.size() == table_name.size() &&
                std::equal(tref.table.begin(), tref.table.end(),
                           table_name.begin(), table_name.end(),
                           [](char a, char b) {
                               return std::tolower(static_cast<unsigned char>(a)) ==
                                      std::tolower(static_cast<unsigned char>(b));
                           })) {
                references_table = true;
                break;
            }
        }
        if (references_table) {
            cache_map_.erase((*it)->fingerprint.hash);
            it = lru_list_.erase(it);
            ++count;
        } else {
            ++it;
        }
    }
    return count;
}

void ParseCache::Shard::evict_lru() {
    // Assumes mutex is already held

    if (lru_list_.empty()) {
        return;
    }

    // Remove least recently used (back of list)
    auto& back_info = lru_list_.back();
    cache_map_.erase(back_info->fingerprint.hash);
    lru_list_.pop_back();

    ++evictions_;
}

} // namespace sqlproxy
