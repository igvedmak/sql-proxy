#pragma once

#include "security/ikey_manager.hpp"
#include "core/types.hpp"
#include "analyzer/sql_analyzer.hpp"

#include <memory>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace sqlproxy {

struct EncryptionColumnConfig {
    std::string database;
    std::string table;
    std::string column;
};

class ColumnEncryptor {
public:
    struct Config {
        bool enabled = false;
        std::vector<EncryptionColumnConfig> columns;
    };

    ColumnEncryptor(std::shared_ptr<IKeyManager> key_manager, const Config& config);

    void decrypt_result(QueryResult& result,
                        const std::string& database,
                        const AnalysisResult& analysis);

    [[nodiscard]] bool is_encrypted_column(
        const std::string& database,
        const std::string& table,
        const std::string& column) const;

    [[nodiscard]] std::string encrypt(std::string_view plaintext) const;
    [[nodiscard]] std::string decrypt(std::string_view ciphertext) const;

    [[nodiscard]] bool is_enabled() const { return config_.enabled; }

private:
    std::shared_ptr<IKeyManager> key_manager_;
    Config config_;
    std::unordered_set<std::string> encrypted_columns_;

    static std::string make_column_key(const std::string& db,
                                        const std::string& table,
                                        const std::string& col);
};

} // namespace sqlproxy
