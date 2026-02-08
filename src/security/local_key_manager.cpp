#include "security/local_key_manager.hpp"

#include <fstream>
#include <mutex>
#include <random>
#include <sstream>
#include <iomanip>

namespace sqlproxy {

LocalKeyManager::LocalKeyManager(const std::string& key_file)
    : key_file_(key_file) {
    if (!key_file_.empty()) {
        load_keys();
    }
    // If no keys loaded, generate a default one
    if (keys_.empty()) {
        generate_and_add_key();
    }
}

std::optional<IKeyManager::KeyInfo> LocalKeyManager::get_active_key() const {
    std::shared_lock lock(mutex_);
    if (keys_.empty()) return std::nullopt;
    if (active_index_ < keys_.size()) {
        return keys_[active_index_];
    }
    return std::nullopt;
}

std::optional<IKeyManager::KeyInfo> LocalKeyManager::get_key(const std::string& key_id) const {
    std::shared_lock lock(mutex_);
    for (const auto& key : keys_) {
        if (key.key_id == key_id) {
            return key;
        }
    }
    return std::nullopt;
}

bool LocalKeyManager::rotate_key() {
    std::unique_lock lock(mutex_);

    // Mark current active key as inactive
    if (active_index_ < keys_.size()) {
        keys_[active_index_].active = false;
    }

    // Generate new key
    KeyInfo new_key;
    new_key.key_id = generate_key_id();
    new_key.key_bytes = generate_key();
    new_key.created_at = std::chrono::system_clock::now();
    new_key.active = true;

    keys_.push_back(std::move(new_key));
    active_index_ = keys_.size() - 1;

    if (!key_file_.empty()) {
        save_keys();
    }
    return true;
}

size_t LocalKeyManager::key_count() const {
    std::shared_lock lock(mutex_);
    return keys_.size();
}

bool LocalKeyManager::generate_and_add_key() {
    std::unique_lock lock(mutex_);

    KeyInfo key;
    key.key_id = generate_key_id();
    key.key_bytes = generate_key();
    key.created_at = std::chrono::system_clock::now();
    key.active = true;

    // Deactivate previous active key
    if (!keys_.empty() && active_index_ < keys_.size()) {
        keys_[active_index_].active = false;
    }

    keys_.push_back(std::move(key));
    active_index_ = keys_.size() - 1;

    if (!key_file_.empty()) {
        save_keys();
    }
    return true;
}

void LocalKeyManager::load_keys() {
    std::ifstream file(key_file_);
    if (!file.is_open()) return;

    // Simple line-based format: key_id:hex_encoded_key:active
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        size_t first_colon = line.find(':');
        if (first_colon == std::string::npos) continue;
        size_t second_colon = line.find(':', first_colon + 1);
        if (second_colon == std::string::npos) continue;

        KeyInfo key;
        key.key_id = line.substr(0, first_colon);
        std::string hex_key = line.substr(first_colon + 1, second_colon - first_colon - 1);
        std::string active_str = line.substr(second_colon + 1);

        // Decode hex
        key.key_bytes.reserve(hex_key.size() / 2);
        for (size_t i = 0; i + 1 < hex_key.size(); i += 2) {
            uint8_t byte = static_cast<uint8_t>(
                std::stoi(hex_key.substr(i, 2), nullptr, 16));
            key.key_bytes.push_back(byte);
        }

        key.active = (active_str == "1" || active_str == "true");
        key.created_at = std::chrono::system_clock::now();

        if (key.active) {
            active_index_ = keys_.size();
        }
        keys_.push_back(std::move(key));
    }
}

void LocalKeyManager::save_keys() {
    if (key_file_.empty()) return;

    std::ofstream file(key_file_);
    if (!file.is_open()) return;

    file << "# Key format: key_id:hex_key:active\n";
    for (const auto& key : keys_) {
        file << key.key_id << ':';
        for (uint8_t byte : key.key_bytes) {
            file << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
        }
        file << ':' << (key.active ? "1" : "0") << '\n';
    }
}

std::vector<uint8_t> LocalKeyManager::generate_key() {
    std::vector<uint8_t> key(32); // 256 bits
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto& byte : key) {
        byte = static_cast<uint8_t>(dist(gen));
    }
    return key;
}

std::string LocalKeyManager::generate_key_id() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist;

    std::ostringstream oss;
    oss << "key-" << std::hex << dist(gen) << dist(gen);
    return oss.str();
}

} // namespace sqlproxy
