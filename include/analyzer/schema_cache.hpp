#pragma once

#include "core/types.hpp"
#include <string>
#include <memory>
#include <atomic>
#include <mutex>
#include <functional>
#include <thread>

namespace sqlproxy {

/**
 * @brief Schema cache with RCU (Read-Copy-Update) for hot reload
 *
 * Preloads table metadata from information_schema at startup.
 * Provides zero-cost reads via atomic shared_ptr.
 * Hot-reloadable on DDL operations via RCU pointer swap.
 *
 * RCU benefits:
 * - Readers never block (atomic load)
 * - Writers build new cache offline, then atomic swap
 * - In-flight requests see old schema, new requests see new
 * - Zero downtime on schema changes
 *
 * Staleness window: ~100ms after DDL (documented tradeoff)
 *
 * Thread-safety: Multiple readers + single writer safe
 */
class SchemaCache {
public:
    /**
     * @brief Callback for loading schema from database
     *
     * Takes database connection info, returns SchemaCache map.
     * Allows dependency injection for testing.
     */
    using LoaderFunc = std::function<SchemaMap(const std::string& conn_string)>;

    /**
     * @brief Construct empty schema cache
     */
    SchemaCache();

    /**
     * @brief Construct and load schema from database
     * @param conn_string PostgreSQL connection string
     */
    explicit SchemaCache(const std::string& conn_string);

    ~SchemaCache() = default;

    /**
     * @brief Get table metadata (read-only, wait-free)
     * @param table_name Fully qualified table name (schema.table or just table)
     * @return Table metadata, or nullptr if not found
     */
    std::shared_ptr<const TableMetadata> get_table(const std::string& table_name) const;

    /**
     * @brief Check if table exists
     */
    bool has_table(const std::string& table_name) const;

    /**
     * @brief Reload schema from database (RCU update)
     * @param conn_string PostgreSQL connection string
     * @return true if reload succeeded
     */
    bool reload(const std::string& conn_string);

    /**
     * @brief Get current schema version
     * @return Monotonic version counter
     */
    uint64_t version() const {
        return version_.load(std::memory_order_acquire);
    }

    /**
     * @brief Get all cached tables (snapshot copy, wait-free read)
     * @return Copy of the schema map (shared_ptrs are cheap to copy)
     */
    [[nodiscard]] SchemaMap get_all_tables() const;

    /**
     * @brief Get number of cached tables
     */
    size_t table_count() const;

    /**
     * @brief Clear cache
     */
    void clear();

    /**
     * @brief Set custom loader function (for testing)
     */
    void set_loader(LoaderFunc loader) {
        loader_ = std::move(loader);
    }

private:
    /**
     * @brief Load schema from PostgreSQL information_schema
     * @param conn_string PostgreSQL connection string
     * @return Loaded schema cache
     */
    static std::shared_ptr<::sqlproxy::SchemaMap> load_from_database(
        const std::string& conn_string);

    /**
     * @brief Normalize table name for lookup
     * @param table_name Input table name
     * @return Normalized name (lowercase, qualified if needed)
     */
    static std::string normalize_table_name(const std::string& table_name);

    // RCU: Readers load this shared_ptr atomically (C++11 compatible)
    std::shared_ptr<::sqlproxy::SchemaMap> cache_ptr_;

    // Version counter (incremented on each reload)
    std::atomic<uint64_t> version_;

    // Mutex for writers (only one reload at a time)
    mutable std::mutex reload_mutex_;

    // Custom loader (for testing)
    LoaderFunc loader_;
};

/**
 * @brief RAII helper for schema cache invalidation
 *
 * Triggers async schema reload on destruction.
 * Use after successful DDL execution.
 *
 * Uses shared_ptr to SchemaCache to prevent use-after-free if the cache
 * is destroyed before the background reload thread completes.
 */
class SchemaInvalidator {
public:
    explicit SchemaInvalidator(std::shared_ptr<SchemaCache> cache, std::string conn_string)
        : cache_(std::move(cache)), conn_string_(std::move(conn_string)) {}

    // Non-shared_ptr overload for backward compatibility (wraps in aliasing shared_ptr)
    explicit SchemaInvalidator(SchemaCache& cache, std::string conn_string)
        : cache_(std::shared_ptr<SchemaCache>(&cache, [](SchemaCache*){})),
          conn_string_(std::move(conn_string)) {}

    ~SchemaInvalidator() {
        // Background reload with shared_ptr ownership — prevents dangling reference
        auto cache_ptr = cache_;
        auto cs = std::move(conn_string_);
        std::thread([cache_ptr = std::move(cache_ptr), cs = std::move(cs)]() {
            cache_ptr->reload(cs);
        }).detach();
    }

    SchemaInvalidator(const SchemaInvalidator&) = delete;
    SchemaInvalidator& operator=(const SchemaInvalidator&) = delete;
    SchemaInvalidator(SchemaInvalidator&&) = default;
    SchemaInvalidator& operator=(SchemaInvalidator&&) = default;

private:
    std::shared_ptr<SchemaCache> cache_;
    std::string conn_string_;
};

} // namespace sqlproxy
