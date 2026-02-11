#pragma once

#include <openssl/ssl.h>
#include <cstddef>
#include <sys/types.h>

namespace sqlproxy {

/**
 * @brief RAII wrapper for OpenSSL SSL connection on a raw socket fd.
 *
 * After PostgreSQL SSLRequest negotiation, the server sends 'S' and then
 * performs a TLS handshake on the existing TCP connection. This class wraps
 * that handshake and provides SSL_read/SSL_write for subsequent I/O.
 *
 * Usage:
 *   // After sending 'S' byte to client
 *   auto ssl = std::make_unique<SslConnection>(fd, ssl_ctx);
 *   if (!ssl->is_valid()) { <handshake failed> }
 *   ssl->read(buf, len);   // instead of recv()
 *   ssl->write(buf, len);  // instead of send()
 */
class SslConnection {
public:
    /**
     * @brief Construct and perform TLS server-side handshake.
     * @param fd Raw TCP socket (already connected)
     * @param ctx SSL_CTX* with cert/key loaded (shared across connections)
     */
    SslConnection(int fd, SSL_CTX* ctx);

    ~SslConnection();

    // Non-copyable
    SslConnection(const SslConnection&) = delete;
    SslConnection& operator=(const SslConnection&) = delete;

    // Movable
    SslConnection(SslConnection&& other) noexcept;
    SslConnection& operator=(SslConnection&& other) noexcept;

    /** @brief Returns true if handshake succeeded */
    [[nodiscard]] bool is_valid() const { return ssl_ != nullptr && valid_; }

    /**
     * @brief Read data from the TLS connection.
     * @return Bytes read, 0 on EOF, -1 on error.
     */
    ssize_t read(void* buf, size_t len);

    /**
     * @brief Read exactly `len` bytes (blocking), similar to MSG_WAITALL.
     * @return true if all bytes read, false on error/EOF.
     */
    bool read_exact(void* buf, size_t len);

    /**
     * @brief Write data to the TLS connection.
     * @return Bytes written, or -1 on error.
     */
    ssize_t write(const void* buf, size_t len);

    /**
     * @brief Write all bytes (blocking loop).
     * @return true if all bytes sent, false on error.
     */
    bool write_all(const void* buf, size_t len);

private:
    SSL* ssl_ = nullptr;
    int fd_ = -1;
    bool valid_ = false;
};

} // namespace sqlproxy
