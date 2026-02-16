#include "server/wire_server.hpp"
#include "core/utils.hpp"

#include <format>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <openssl/err.h>

namespace sqlproxy {

WireServer::WireServer(std::shared_ptr<Pipeline> pipeline,
                       const WireProtocolConfig& config,
                       std::unordered_map<std::string, UserInfo> users)
    : pipeline_(std::move(pipeline)),
      config_(config),
      users_(std::move(users)) {}

WireServer::~WireServer() {
    stop();
    cleanup_ssl_context();
}

void WireServer::init_ssl_context() {
    if (!config_.tls.enabled) return;

    // RAII guard: automatically frees SSL_CTX if any setup step throws
    struct SslCtxDeleter { void operator()(SSL_CTX* p) { if (p) SSL_CTX_free(p); } };
    std::unique_ptr<SSL_CTX, SslCtxDeleter> ctx_guard(SSL_CTX_new(TLS_server_method()));
    if (!ctx_guard) {
        throw std::runtime_error("Wire TLS: failed to create SSL_CTX");
    }

    auto* ctx = ctx_guard.get();

    // Set minimum TLS version to 1.2
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    // Load server certificate
    if (SSL_CTX_use_certificate_file(ctx, config_.tls.cert_file.c_str(), SSL_FILETYPE_PEM) != 1) {
        throw std::runtime_error(std::format("Wire TLS: failed to load certificate: {}",
            config_.tls.cert_file));
    }

    // Load private key
    if (SSL_CTX_use_PrivateKey_file(ctx, config_.tls.key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
        throw std::runtime_error(std::format("Wire TLS: failed to load private key: {}",
            config_.tls.key_file));
    }

    // Verify private key matches certificate
    if (SSL_CTX_check_private_key(ctx) != 1) {
        throw std::runtime_error("Wire TLS: private key does not match certificate");
    }

    // Optional: mTLS (client certificate verification)
    if (config_.tls.require_client_cert && !config_.tls.ca_file.empty()) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        if (SSL_CTX_load_verify_locations(ctx, config_.tls.ca_file.c_str(), nullptr) != 1) {
            throw std::runtime_error(std::format("Wire TLS: failed to load CA certificate: {}",
                config_.tls.ca_file));
        }
    }

    // Transfer ownership — RAII guard releases, ssl_ctx_ takes over
    ssl_ctx_ = ctx_guard.release();

    utils::log::info(std::format("Wire TLS: initialized (cert={}, key={}{})",
        config_.tls.cert_file, config_.tls.key_file,
        config_.tls.require_client_cert ? ", mTLS enabled" : ""));
}

void WireServer::cleanup_ssl_context() {
    if (ssl_ctx_) {
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
    }
}

void WireServer::start() {
    if (running_.load()) return;

    // Initialize TLS if configured
    init_ssl_context();

    // Create TCP socket
    server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        throw std::runtime_error(std::format("Wire: socket() failed: {}", strerror(errno)));
    }

    // SO_REUSEADDR
    int opt = 1;
    setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Bind
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.port);
    inet_aton(config_.host.c_str(), &addr.sin_addr);

    if (bind(server_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(server_fd_);
        throw std::runtime_error(std::format("Wire: bind({}:{}) failed: {}",
            config_.host, config_.port, strerror(errno)));
    }

    if (listen(server_fd_, 128) < 0) {
        close(server_fd_);
        throw std::runtime_error(std::format("Wire: listen() failed: {}", strerror(errno)));
    }

    running_.store(true);

    // Start accept thread
    accept_thread_ = std::jthread([this](std::stop_token) { accept_loop(); });

    utils::log::info(std::format("Wire protocol server listening on {}:{}{}",
        config_.host, config_.port,
        ssl_ctx_ ? " (TLS available)" : ""));
}

void WireServer::stop() {
    if (!running_.exchange(false)) return;

    if (server_fd_ >= 0) {
        shutdown(server_fd_, SHUT_RDWR);
        close(server_fd_);
        server_fd_ = -1;
    }

    if (accept_thread_.joinable()) {
        accept_thread_.request_stop();
        accept_thread_.join();
    }

    for (auto& w : workers_) {
        if (w.joinable()) w.join();
    }
    workers_.clear();

    utils::log::info("Wire protocol server stopped");
}

void WireServer::accept_loop() {
    while (running_.load()) {
        struct sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);

        const int client_fd = accept(server_fd_,
            reinterpret_cast<struct sockaddr*>(&client_addr), &addr_len);

        if (client_fd < 0) {
            if (!running_.load()) break;  // Shutting down
            continue;
        }

        // Check connection limit
        if (active_connections_.load() >= config_.max_connections) {
            close(client_fd);
            continue;
        }

        std::string remote_addr = std::format("{}:{}",
            inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // Spawn worker thread for this connection
        active_connections_.fetch_add(1);
        workers_.emplace_back([this, client_fd, addr = std::move(remote_addr)]() {
            handle_connection(client_fd, std::move(addr));
            active_connections_.fetch_sub(1);
        });
    }
}

void WireServer::handle_connection(int client_fd, std::string remote_addr) {
    auto user_lookup = [this](const std::string& username) -> std::optional<UserInfo> {
        return lookup_user(username);
    };

    WireSession session(client_fd, std::move(remote_addr), pipeline_,
                        std::move(user_lookup), config_.require_password,
                        ssl_ctx_, config_.prefer_scram, config_.scram_iterations);
    session.run();
}

std::optional<UserInfo> WireServer::lookup_user(const std::string& username) const {
    std::shared_lock lock(users_mutex_);
    const auto it = users_.find(username);
    if (it != users_.end()) {
        return it->second;
    }
    // Development mode: if no users configured, allow all
    if (users_.empty()) {
        return UserInfo(std::string(username), {"user"});
    }
    return std::nullopt;
}

void WireServer::update_users(std::unordered_map<std::string, UserInfo> users) {
    std::unique_lock lock(users_mutex_);
    users_ = std::move(users);
}

} // namespace sqlproxy
