#pragma once

#include "plugin/plugin_interface.hpp"
#include <memory>
#include <string>
#include <vector>

namespace sqlproxy {

struct PluginConfig {
    std::string path;       // Path to .so file
    std::string type;       // "classifier" or "audit_sink"
    std::string config;     // JSON config string passed to plugin
};

// RAII wrapper for a loaded shared library
class LoadedPlugin {
public:
    LoadedPlugin(std::string path, std::string type, void* handle);
    ~LoadedPlugin();

    // Non-copyable, movable
    LoadedPlugin(const LoadedPlugin&) = delete;
    LoadedPlugin& operator=(const LoadedPlugin&) = delete;
    LoadedPlugin(LoadedPlugin&& other) noexcept;
    LoadedPlugin& operator=(LoadedPlugin&& other) noexcept;

    [[nodiscard]] const std::string& path() const { return path_; }
    [[nodiscard]] const std::string& type() const { return type_; }
    [[nodiscard]] void* handle() const { return handle_; }

    // Resolve symbol from the shared library
    [[nodiscard]] void* resolve(const char* symbol) const;

private:
    std::string path_;
    std::string type_;
    void* handle_;

public:
    // Plugin instances (owned, destroyed on unload)
    ClassifierPlugin* classifier = nullptr;
    AuditSinkPlugin* audit_sink = nullptr;
};

class PluginRegistry {
public:
    PluginRegistry() = default;
    ~PluginRegistry();

    // Non-copyable
    PluginRegistry(const PluginRegistry&) = delete;
    PluginRegistry& operator=(const PluginRegistry&) = delete;

    // Load a plugin from config (dlopen + resolve factory)
    [[nodiscard]] bool load_plugin(const PluginConfig& config);

    // Access loaded plugins
    [[nodiscard]] const std::vector<ClassifierPlugin*>& classifier_plugins() const {
        return classifiers_;
    }
    [[nodiscard]] const std::vector<AuditSinkPlugin*>& audit_sink_plugins() const {
        return audit_sinks_;
    }

    [[nodiscard]] size_t plugin_count() const { return plugins_.size(); }

    // Unload all plugins (called in destructor)
    void unload_all();

private:
    std::vector<std::unique_ptr<LoadedPlugin>> plugins_;
    std::vector<ClassifierPlugin*> classifiers_;
    std::vector<AuditSinkPlugin*> audit_sinks_;
};

} // namespace sqlproxy
