#include "security/column_encryptor.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstring>
#include <stdexcept>

namespace sqlproxy {

namespace {

// Base64 encode/decode helpers
static const char kBase64Chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const uint8_t* data, size_t len) {
    std::string result;
    result.reserve(4 * ((len + 2) / 3));

    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);

        result += kBase64Chars[(n >> 18) & 0x3F];
        result += kBase64Chars[(n >> 12) & 0x3F];
        result += (i + 1 < len) ? kBase64Chars[(n >> 6) & 0x3F] : '=';
        result += (i + 2 < len) ? kBase64Chars[n & 0x3F] : '=';
    }
    return result;
}

std::vector<uint8_t> base64_decode(const std::string& encoded) {
    static const uint8_t kDecodeTable[128] = {
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,62,64,64,64,63,
        52,53,54,55,56,57,58,59,60,61,64,64,64,64,64,64,
        64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,64,64,64,64,64,
        64,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,64,64,64,64,64
    };

    std::vector<uint8_t> result;
    result.reserve(3 * encoded.size() / 4);

    uint32_t buf = 0;
    int bits = 0;
    for (char c : encoded) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        if (static_cast<unsigned char>(c) >= 128) continue;
        uint8_t val = kDecodeTable[static_cast<unsigned char>(c)];
        if (val == 64) continue;

        buf = (buf << 6) | val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            result.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
        }
    }
    return result;
}

// AES-256-GCM constants
constexpr int kIvLen = 12;
constexpr int kTagLen = 16;
constexpr int kKeyLen = 32;

} // anonymous namespace

ColumnEncryptor::ColumnEncryptor(std::shared_ptr<IKeyManager> key_manager,
                                 const Config& config)
    : key_manager_(std::move(key_manager)), config_(config) {
    // Build lookup set for O(1) column checks
    for (const auto& col : config_.columns) {
        encrypted_columns_.insert(make_column_key(col.database, col.table, col.column));
    }
}

std::string ColumnEncryptor::make_column_key(const std::string& db,
                                              const std::string& table,
                                              const std::string& col) {
    std::string key;
    key.reserve(db.size() + 1 + table.size() + 1 + col.size());
    key = db;
    key += '.';
    key += table;
    key += '.';
    key += col;
    return key;
}

bool ColumnEncryptor::is_encrypted_column(const std::string& database,
                                           const std::string& table,
                                           const std::string& column) const {
    return encrypted_columns_.contains(make_column_key(database, table, column));
}

std::string ColumnEncryptor::encrypt(std::string_view plaintext) const {
    auto key_info = key_manager_->get_active_key();
    if (!key_info || key_info->key_bytes.size() < kKeyLen) {
        return std::string(plaintext); // Passthrough if no key
    }

    // Generate random IV
    uint8_t iv[kIvLen];
    RAND_bytes(iv, kIvLen);

    // Encrypt with AES-256-GCM
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::string(plaintext);

    std::vector<uint8_t> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    uint8_t tag[kTagLen];
    int len = 0;
    int ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kIvLen, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_info->key_bytes.data(), iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
        reinterpret_cast<const uint8_t*>(plaintext.data()),
        static_cast<int>(plaintext.size()));
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagLen, tag);
    EVP_CIPHER_CTX_free(ctx);

    // Pack: iv + ciphertext + tag
    std::vector<uint8_t> packed;
    packed.reserve(kIvLen + ciphertext_len + kTagLen);
    packed.insert(packed.end(), iv, iv + kIvLen);
    packed.insert(packed.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);
    packed.insert(packed.end(), tag, tag + kTagLen);

    // Format: ENC:v1:<key_id>:<base64(packed)>
    std::string result = "ENC:v1:";
    result += key_info->key_id;
    result += ':';
    result += base64_encode(packed.data(), packed.size());
    return result;
}

std::string ColumnEncryptor::decrypt(std::string_view ciphertext) const {
    // Check format: ENC:v1:<key_id>:<base64>
    constexpr std::string_view kPrefix = "ENC:v1:";
    if (ciphertext.size() < kPrefix.size() ||
        ciphertext.substr(0, kPrefix.size()) != kPrefix) {
        return std::string(ciphertext); // Not encrypted, passthrough
    }

    auto rest = ciphertext.substr(kPrefix.size());
    size_t colon = rest.find(':');
    if (colon == std::string_view::npos) {
        return std::string(ciphertext);
    }

    std::string key_id(rest.substr(0, colon));
    std::string b64_data(rest.substr(colon + 1));

    auto key_info = key_manager_->get_key(key_id);
    if (!key_info || key_info->key_bytes.size() < kKeyLen) {
        return std::string(ciphertext); // Key not found
    }

    auto packed = base64_decode(b64_data);
    if (packed.size() < kIvLen + kTagLen) {
        return std::string(ciphertext); // Too short
    }

    const uint8_t* iv = packed.data();
    size_t ct_len = packed.size() - kIvLen - kTagLen;
    const uint8_t* ct = packed.data() + kIvLen;
    const uint8_t* tag = packed.data() + kIvLen + ct_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::string(ciphertext);

    std::vector<uint8_t> plaintext(ct_len + EVP_MAX_BLOCK_LENGTH);
    int len = 0;
    int plaintext_len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kIvLen, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_info->key_bytes.data(), iv);
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ct, static_cast<int>(ct_len));
    plaintext_len = len;

    // Set expected tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kTagLen,
        const_cast<uint8_t*>(tag));

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        return std::string(ciphertext); // Authentication failed
    }
    plaintext_len += len;

    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}

void ColumnEncryptor::decrypt_result(QueryResult& result,
                                      const std::string& database,
                                      const AnalysisResult& analysis) {
    if (!config_.enabled || !key_manager_) return;
    if (result.column_names.empty() || result.rows.empty()) return;

    // Find which columns need decryption
    std::vector<size_t> decrypt_indices;
    for (size_t i = 0; i < result.column_names.size(); ++i) {
        const auto& col_name = result.column_names[i];
        // Check against all source tables
        for (const auto& table_ref : analysis.source_tables) {
            if (is_encrypted_column(database, table_ref.table, col_name)) {
                decrypt_indices.push_back(i);
                break;
            }
        }
    }

    if (decrypt_indices.empty()) return;

    // Decrypt matching columns in all rows
    for (auto& row : result.rows) {
        for (size_t idx : decrypt_indices) {
            if (idx < row.size()) {
                row[idx] = decrypt(row[idx]);
            }
        }
    }
}

} // namespace sqlproxy
