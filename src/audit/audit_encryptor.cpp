#include "audit/audit_encryptor.hpp"
#include "core/base64.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstring>

namespace sqlproxy {

namespace {
constexpr int kIvLen = 12;
constexpr int kTagLen = 16;
constexpr int kKeyLen = 32;
constexpr std::string_view kPrefix = "AENC:v1:";
} // anonymous namespace

AuditEncryptor::AuditEncryptor(std::shared_ptr<IKeyManager> key_manager,
                               const Config& config)
    : key_manager_(std::move(key_manager)), config_(config) {}

std::string AuditEncryptor::encrypt(std::string_view plaintext) const {
    if (!config_.enabled || !key_manager_) {
        return std::string(plaintext);
    }

    const auto key_info = key_manager_->get_active_key();
    if (!key_info || key_info->key_bytes.size() < kKeyLen) {
        encryption_failures_.fetch_add(1, std::memory_order_relaxed);
        return std::string(plaintext);
    }

    // Generate random IV
    uint8_t iv[kIvLen];
    RAND_bytes(iv, kIvLen);

    // Encrypt with AES-256-GCM
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        encryption_failures_.fetch_add(1, std::memory_order_relaxed);
        return std::string(plaintext);
    }

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

    // Format: AENC:v1:<key_id>:<base64(packed)>
    std::string result;
    result.reserve(kPrefix.size() + config_.key_id.size() + 1 +
                   4 * ((packed.size() + 2) / 3));
    result += kPrefix;
    result += config_.key_id;
    result += ':';
    result += base64::encode(packed.data(), packed.size());

    records_encrypted_.fetch_add(1, std::memory_order_relaxed);
    return result;
}

std::string AuditEncryptor::decrypt(std::string_view ciphertext) const {
    // Check format: AENC:v1:<key_id>:<base64>
    if (ciphertext.size() < kPrefix.size() ||
        ciphertext.substr(0, kPrefix.size()) != kPrefix) {
        return std::string(ciphertext); // Not encrypted, passthrough
    }

    const auto rest = ciphertext.substr(kPrefix.size());
    const size_t colon = rest.find(':');
    if (colon == std::string_view::npos) {
        return std::string(ciphertext);
    }

    std::string key_id(rest.substr(0, colon));
    std::string b64_data(rest.substr(colon + 1));

    const auto key_info = key_manager_->get_key(key_id);
    if (!key_info || key_info->key_bytes.size() < kKeyLen) {
        return std::string(ciphertext);
    }

    const auto packed = base64::decode(b64_data);
    if (packed.size() < kIvLen + kTagLen) {
        return std::string(ciphertext);
    }

    const uint8_t* iv = packed.data();
    size_t ct_len = packed.size() - kIvLen - kTagLen;
    const uint8_t* ct = packed.data() + kIvLen;
    const uint8_t* tag_ptr = packed.data() + kIvLen + ct_len;

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

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kTagLen,
        const_cast<uint8_t*>(tag_ptr));

    const int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        return std::string(ciphertext); // Authentication failed
    }
    plaintext_len += len;

    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}

} // namespace sqlproxy
