#pragma once

#include "security/ikey_manager.hpp"
#include <atomic>
#include <memory>
#include <string>
#include <string_view>

namespace sqlproxy {

/**
 * @brief Encrypts audit records at rest using AES-256-GCM
 *
 * Each record is independently encrypted with a random IV.
 * Format: AENC:v1:<key_id>:<base64(iv + ciphertext + tag)>
 *
 * Reuses the same AES-256-GCM pattern as ColumnEncryptor.
 * Hash chain integrity is computed on plaintext before encryption.
 */
class AuditEncryptor {
public:
    struct Config {
        bool enabled = false;
        std::string key_id = "audit-key-1";
    };

    AuditEncryptor(std::shared_ptr<IKeyManager> key_manager, const Config& config);

    /// Encrypt a JSON audit record string
    [[nodiscard]] std::string encrypt(std::string_view plaintext) const;

    /// Decrypt an encrypted audit record
    [[nodiscard]] std::string decrypt(std::string_view ciphertext) const;

    [[nodiscard]] bool is_enabled() const { return config_.enabled; }

    struct Stats {
        uint64_t records_encrypted;
        uint64_t encryption_failures;
    };

    [[nodiscard]] Stats get_stats() const {
        return {
            .records_encrypted = records_encrypted_.load(std::memory_order_relaxed),
            .encryption_failures = encryption_failures_.load(std::memory_order_relaxed),
        };
    }

private:
    std::shared_ptr<IKeyManager> key_manager_;
    Config config_;
    mutable std::atomic<uint64_t> records_encrypted_{0};
    mutable std::atomic<uint64_t> encryption_failures_{0};
};

} // namespace sqlproxy
