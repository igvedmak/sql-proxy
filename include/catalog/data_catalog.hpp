#pragma once

#include "core/types.hpp"
#include "analyzer/sql_analyzer.hpp"
#include "policy/policy_types.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <shared_mutex>
#include <chrono>
#include <atomic>
#include <algorithm>

namespace sqlproxy {

struct CatalogColumn {
    std::string table;              // Fully qualified: "schema.table"
    std::string column;
    std::string data_type;          // From SchemaCache: "integer", "text", etc.
    ClassificationType pii_type = ClassificationType::NONE;
    double confidence = 0.0;        // Highest confidence seen
    std::string strategy;           // Classification strategy that classified it
    uint64_t access_count = 0;
    uint64_t masked_count = 0;
    std::unordered_set<std::string> accessing_users;
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_accessed;
    bool is_primary_key = false;
    bool is_nullable = true;
};

struct CatalogTable {
    std::string name;               // Fully qualified: "schema.table"
    std::string schema;
    std::string database;
    uint64_t total_accesses = 0;
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_accessed;
    std::vector<std::string> column_names;  // Ordered
};

struct CatalogSearchResult {
    std::string table;
    std::string column;
    ClassificationType pii_type;
    double confidence;
    uint64_t access_count;
};

class DataCatalog {
public:
    struct Config {
        bool enabled = true;
        size_t max_tables = 10000;
        size_t max_columns_per_table = 500;
    };

    struct Stats {
        size_t total_tables = 0;
        size_t total_columns = 0;
        size_t pii_columns = 0;
        uint64_t total_classifications_recorded = 0;
    };

    DataCatalog() = default;
    explicit DataCatalog(Config config);

    // --- Ingestion (called from pipeline after classification) ---

    /**
     * @brief Record classification results for a query.
     * Thread-safe. Called from Pipeline after classify_results().
     */
    void record_classifications(
        const std::string& database,
        const std::string& user,
        const AnalysisResult& analysis,
        const ClassificationResult& classification,
        const std::vector<MaskingRecord>& masking_applied);

    /**
     * @brief Seed catalog with schema metadata (no classification).
     * Called once at startup from SchemaCache.
     */
    void seed_from_schema(const SchemaMap& schema);

    // --- Query API ---

    [[nodiscard]] std::vector<CatalogTable> get_tables() const;

    [[nodiscard]] std::vector<CatalogColumn> get_columns(const std::string& table) const;

    /** Search columns by PII type. If type == NONE, return all PII columns. */
    [[nodiscard]] std::vector<CatalogSearchResult> search_pii(
        ClassificationType type = ClassificationType::NONE) const;

    /** Case-insensitive substring search across table and column names */
    [[nodiscard]] std::vector<CatalogSearchResult> search(
        const std::string& query) const;

    [[nodiscard]] Stats get_stats() const;

private:
    Config config_;

    // table_key -> CatalogTable
    std::unordered_map<std::string, CatalogTable> tables_;

    // "table.column" -> CatalogColumn
    std::unordered_map<std::string, CatalogColumn> columns_;

    mutable std::shared_mutex mutex_;

    std::atomic<uint64_t> total_recorded_{0};
};

} // namespace sqlproxy
