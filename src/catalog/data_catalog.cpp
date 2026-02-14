#include "catalog/data_catalog.hpp"
#include "core/utils.hpp"

#include <algorithm>

namespace sqlproxy {

DataCatalog::DataCatalog(Config config)
    : config_(std::move(config)) {}

// ============================================================================
// Ingestion
// ============================================================================

void DataCatalog::record_classifications(
    const std::string& database,
    const std::string& user,
    const AnalysisResult& analysis,
    const ClassificationResult& classification,
    const std::vector<MaskingRecord>& masking_applied) {

    if (!config_.enabled) return;
    if (classification.classifications.empty()) return;

    const auto now = std::chrono::system_clock::now();

    // Build set of masked columns for quick lookup
    std::unordered_set<std::string> masked_cols;
    for (const auto& m : masking_applied) {
        masked_cols.insert(m.column_name);
    }

    // Determine table name from analysis
    std::string table_key;
    if (!analysis.source_tables.empty()) {
        const auto& t = analysis.source_tables[0];
        table_key = t.schema.empty() ? t.table : (t.schema + "." + t.table);
    }

    std::unique_lock lock(mutex_);

    // Upsert table
    if (!table_key.empty()) {
        auto& tbl = tables_[table_key];
        if (tbl.name.empty()) {
            tbl.name = table_key;
            tbl.database = database;
            tbl.first_seen = now;
            if (!analysis.source_tables.empty()) {
                tbl.schema = analysis.source_tables[0].schema;
            }
        }
        ++tbl.total_accesses;
        tbl.last_accessed = now;
    }

    // Upsert columns with classifications
    for (const auto& [col_name, cls] : classification.classifications) {
        std::string col_key;
        if (table_key.empty()) {
            col_key = col_name;
        } else {
            col_key.reserve(table_key.size() + 1 + col_name.size());
            col_key = table_key;
            col_key += '.';
            col_key += col_name;
        }

        auto& col = columns_[col_key];
        if (col.column.empty()) {
            col.table = table_key;
            col.column = col_name;
            col.first_seen = now;
        }

        // Update classification (keep highest confidence)
        if (cls.confidence > col.confidence || col.pii_type == ClassificationType::NONE) {
            col.pii_type = cls.type;
            col.confidence = cls.confidence;
            col.strategy = cls.strategy;
        }

        ++col.access_count;
        col.last_accessed = now;
        col.accessing_users.insert(user);

        if (masked_cols.count(col_name)) {
            ++col.masked_count;
        }

        // Ensure column is in table's column list
        if (!table_key.empty()) {
            auto& tbl = tables_[table_key];
            if (std::find(tbl.column_names.begin(), tbl.column_names.end(), col_name)
                    == tbl.column_names.end()) {
                tbl.column_names.push_back(col_name);
            }
        }
    }

    total_recorded_.fetch_add(1, std::memory_order_relaxed);
}

void DataCatalog::seed_from_schema(const SchemaMap& schema) {
    const auto now = std::chrono::system_clock::now();

    std::unique_lock lock(mutex_);

    for (const auto& [name, meta] : schema) {
        auto& tbl = tables_[name];
        tbl.name = name;
        tbl.schema = meta->schema;
        tbl.first_seen = now;

        for (const auto& col_meta : meta->columns) {
            std::string col_key;
            col_key.reserve(name.size() + 1 + col_meta.name.size());
            col_key = name;
            col_key += '.';
            col_key += col_meta.name;

            auto& col = columns_[col_key];
            col.table = name;
            col.column = col_meta.name;
            col.data_type = col_meta.type;
            col.is_primary_key = col_meta.is_primary_key;
            col.is_nullable = col_meta.nullable;
            col.first_seen = now;

            if (std::find(tbl.column_names.begin(), tbl.column_names.end(), col_meta.name)
                    == tbl.column_names.end()) {
                tbl.column_names.push_back(col_meta.name);
            }
        }
    }
}

// ============================================================================
// Query API
// ============================================================================

std::vector<CatalogTable> DataCatalog::get_tables() const {
    std::shared_lock lock(mutex_);
    std::vector<CatalogTable> result;
    result.reserve(tables_.size());
    for (const auto& [key, tbl] : tables_) {
        result.push_back(tbl);
    }
    return result;
}

std::vector<CatalogColumn> DataCatalog::get_columns(const std::string& table) const {
    std::shared_lock lock(mutex_);
    std::vector<CatalogColumn> result;
    for (const auto& [key, col] : columns_) {
        if (col.table == table) {
            result.push_back(col);
        }
    }
    return result;
}

std::vector<CatalogSearchResult> DataCatalog::search_pii(ClassificationType type) const {
    std::shared_lock lock(mutex_);
    std::vector<CatalogSearchResult> results;
    for (const auto& [key, col] : columns_) {
        if (col.pii_type == ClassificationType::NONE) continue;
        if (type != ClassificationType::NONE && col.pii_type != type) continue;
        results.push_back({col.table, col.column, col.pii_type,
                           col.confidence, col.access_count});
    }
    return results;
}

std::vector<CatalogSearchResult> DataCatalog::search(const std::string& query) const {
    if (query.empty()) return {};

    const auto lower_query = utils::to_lower(query);

    std::shared_lock lock(mutex_);
    std::vector<CatalogSearchResult> results;
    for (const auto& [key, col] : columns_) {
        const auto lower_col = utils::to_lower(col.column);
        const auto lower_table = utils::to_lower(col.table);
        if (lower_col.find(lower_query) != std::string::npos ||
            lower_table.find(lower_query) != std::string::npos) {
            results.push_back({col.table, col.column, col.pii_type,
                               col.confidence, col.access_count});
        }
    }
    return results;
}

DataCatalog::Stats DataCatalog::get_stats() const {
    std::shared_lock lock(mutex_);
    Stats stats;
    stats.total_tables = tables_.size();
    stats.total_columns = columns_.size();
    stats.total_classifications_recorded = total_recorded_.load(std::memory_order_relaxed);

    for (const auto& [key, col] : columns_) {
        if (col.pii_type != ClassificationType::NONE) {
            ++stats.pii_columns;
        }
    }
    return stats;
}

} // namespace sqlproxy
