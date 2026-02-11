#include "server/ssl_connection.hpp"
#include <openssl/err.h>
#include <utility>

namespace sqlproxy {

SslConnection::SslConnection(int fd, SSL_CTX* ctx)
    : fd_(fd) {
    if (!ctx || fd < 0) return;

    ssl_ = SSL_new(ctx);
    if (!ssl_) return;

    if (SSL_set_fd(ssl_, fd) != 1) {
        SSL_free(ssl_);
        ssl_ = nullptr;
        return;
    }

    // Perform server-side TLS handshake
    const int ret = SSL_accept(ssl_);
    if (ret != 1) {
        // Handshake failed — clean up
        SSL_free(ssl_);
        ssl_ = nullptr;
        return;
    }

    valid_ = true;
}

SslConnection::~SslConnection() {
    if (ssl_) {
        // Attempt clean shutdown (ignore errors — socket may already be closed)
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
    }
}

SslConnection::SslConnection(SslConnection&& other) noexcept
    : ssl_(other.ssl_), fd_(other.fd_), valid_(other.valid_) {
    other.ssl_ = nullptr;
    other.fd_ = -1;
    other.valid_ = false;
}

SslConnection& SslConnection::operator=(SslConnection&& other) noexcept {
    if (this != &other) {
        if (ssl_) {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
        }
        ssl_ = other.ssl_;
        fd_ = other.fd_;
        valid_ = other.valid_;
        other.ssl_ = nullptr;
        other.fd_ = -1;
        other.valid_ = false;
    }
    return *this;
}

ssize_t SslConnection::read(void* buf, size_t len) {
    if (!valid_ || !ssl_) return -1;

    const int ret = SSL_read(ssl_, buf, static_cast<int>(len));
    if (ret <= 0) {
        const int err = SSL_get_error(ssl_, ret);
        if (err == SSL_ERROR_ZERO_RETURN) return 0;  // Clean shutdown
        return -1;
    }
    return ret;
}

bool SslConnection::read_exact(void* buf, size_t len) {
    auto* ptr = static_cast<uint8_t*>(buf);
    size_t remaining = len;

    while (remaining > 0) {
        const ssize_t n = read(ptr, remaining);
        if (n <= 0) return false;
        ptr += n;
        remaining -= static_cast<size_t>(n);
    }
    return true;
}

ssize_t SslConnection::write(const void* buf, size_t len) {
    if (!valid_ || !ssl_) return -1;

    const int ret = SSL_write(ssl_, buf, static_cast<int>(len));
    if (ret <= 0) return -1;
    return ret;
}

bool SslConnection::write_all(const void* buf, size_t len) {
    auto* ptr = static_cast<const uint8_t*>(buf);
    size_t remaining = len;

    while (remaining > 0) {
        const ssize_t n = write(ptr, remaining);
        if (n <= 0) return false;
        ptr += n;
        remaining -= static_cast<size_t>(n);
    }
    return true;
}

} // namespace sqlproxy
