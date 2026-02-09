#include "audit/webhook_sink.hpp"
#include "server/http_constants.hpp"
#include "core/utils.hpp"

#include "../third_party/cpp-httplib/httplib.h"

#include <format>

namespace sqlproxy {

WebhookSink::WebhookSink(const Config& config)
    : config_(config) {
    buffer_.reserve(config_.batch_size);

    // Parse URL into host/port/path
    std::string url = config_.url;

    if (url.starts_with("https://")) {
        use_ssl_ = true;
        url = url.substr(8);
        port_ = 443;
    } else if (url.starts_with("http://")) {
        use_ssl_ = false;
        url = url.substr(7);
        port_ = 80;
    }

    auto path_pos = url.find('/');
    if (path_pos != std::string::npos) {
        host_ = url.substr(0, path_pos);
        path_ = url.substr(path_pos);
    } else {
        host_ = url;
        path_ = "/";
    }

    // Check for explicit port
    auto port_pos = host_.find(':');
    if (port_pos != std::string::npos) {
        port_ = std::stoi(host_.substr(port_pos + 1));
        host_ = host_.substr(0, port_pos);
    }
}

WebhookSink::~WebhookSink() {
    shutdown();
}

bool WebhookSink::write(std::string_view json_line) {
    buffer_.emplace_back(json_line);

    if (buffer_.size() >= config_.batch_size) {
        send_batch();
    }

    return true;
}

void WebhookSink::flush() {
    if (!buffer_.empty()) {
        send_batch();
    }
}

void WebhookSink::shutdown() {
    flush();
}

std::string WebhookSink::name() const {
    return "webhook:" + config_.url;
}

void WebhookSink::send_batch() {
    if (buffer_.empty()) return;

    // Build NDJSON payload
    std::string payload;
    for (const auto& line : buffer_) {
        payload += line;
        if (!line.ends_with('\n')) {
            payload += '\n';
        }
    }

    bool success = false;

    for (int attempt = 0; attempt < config_.max_retries && !success; ++attempt) {
        try {
            std::string scheme_host = std::format("{}{}:{}", use_ssl_ ? "https://" : "http://", host_, port_);
            httplib::Client client(scheme_host);
            client.set_connection_timeout(config_.timeout);
            client.set_read_timeout(config_.timeout);

            httplib::Headers headers;
            if (!config_.auth_header.empty()) {
                headers.emplace(http::kAuthorizationHeader, config_.auth_header);
            }

            auto res = client.Post(path_, headers, payload, config_.content_type);
            if (res && res->status >= 200 && res->status < 300) {
                success = true;
            }
        } catch (...) {
            // Swallow exceptions — webhook failures must not block audit
        }
    }

    if (success) {
        ++batches_sent_;
    } else {
        ++send_failures_;
        utils::log::warn(std::format("Webhook sink failed after {} retries: {}",
                                     config_.max_retries, config_.url));
    }

    buffer_.clear();
}

} // namespace sqlproxy
