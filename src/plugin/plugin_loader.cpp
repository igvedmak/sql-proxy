#include "plugin/plugin_loader.hpp"
#include "core/utils.hpp"

#include <dlfcn.h>
#include <format>
#include <algorithm>

namespace sqlproxy {

// ============================================================================
// LoadedPlugin
// ============================================================================

LoadedPlugin::LoadedPlugin(std::string path, std::string type, void* handle)
    : path_(std::move(path)), type_(std::move(type)), handle_(handle) {}

LoadedPlugin::~LoadedPlugin() {
    // Destroy plugin instances before dlclose
    if (classifier && classifier->destroy) {
        classifier->destroy(classifier->instance);
        delete classifier;
    }
    if (audit_sink && audit_sink->destroy) {
        audit_sink->destroy(audit_sink->instance);
        delete audit_sink;
    }
    if (handle_) {
        dlclose(handle_);
    }
}

LoadedPlugin::LoadedPlugin(LoadedPlugin&& other) noexcept
    : path_(std::move(other.path_)),
      type_(std::move(other.type_)),
      handle_(other.handle_),
      classifier(other.classifier),
      audit_sink(other.audit_sink) {
    other.handle_ = nullptr;
    other.classifier = nullptr;
    other.audit_sink = nullptr;
}

LoadedPlugin& LoadedPlugin::operator=(LoadedPlugin&& other) noexcept {
    if (this != &other) {
        path_ = std::move(other.path_);
        type_ = std::move(other.type_);
        handle_ = other.handle_;
        classifier = other.classifier;
        audit_sink = other.audit_sink;
        other.handle_ = nullptr;
        other.classifier = nullptr;
        other.audit_sink = nullptr;
    }
    return *this;
}

void* LoadedPlugin::resolve(const char* symbol) const {
    if (!handle_) return nullptr;
    return dlsym(handle_, symbol);
}

// ============================================================================
// PluginRegistry
// ============================================================================

PluginRegistry::~PluginRegistry() {
    unload_all();
}

bool PluginRegistry::load_plugin(const PluginConfig& config) {
    // dlopen the shared library
    void* handle = dlopen(config.path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        utils::log::error(std::format("Plugin load failed [{}]: {}", config.path, dlerror()));
        return false;
    }

    auto plugin = std::make_unique<LoadedPlugin>(config.path, config.type, handle);

    if (config.type == "classifier") {
        // Resolve factory: ClassifierPlugin* create_classifier_plugin()
        using FactoryFn = ClassifierPlugin* (*)();
        const auto factory = reinterpret_cast<FactoryFn>(plugin->resolve("create_classifier_plugin"));
        if (!factory) {
            utils::log::error(std::format("Plugin [{}]: missing create_classifier_plugin symbol", config.path));
            return false;
        }

        auto* cp = factory();
        if (!cp) {
            utils::log::error(std::format("Plugin [{}]: factory returned null", config.path));
            return false;
        }

        // Validate API version
        const auto info = cp->get_info(cp->instance);
        if (info.api_version != SQLPROXY_PLUGIN_API_VERSION) {
            utils::log::error(std::format("Plugin [{}]: API version mismatch (got {}, expected {})",
                config.path, info.api_version, SQLPROXY_PLUGIN_API_VERSION));
            if (cp->destroy) cp->destroy(cp->instance);
            delete cp;
            return false;
        }

        plugin->classifier = cp;
        utils::log::info(std::format("Plugin loaded: {} v{} (classifier)", info.name, info.version));

    } else if (config.type == "audit_sink") {
        // Resolve factory: AuditSinkPlugin* create_audit_sink_plugin()
        using FactoryFn = AuditSinkPlugin* (*)();
        const auto factory = reinterpret_cast<FactoryFn>(plugin->resolve("create_audit_sink_plugin"));
        if (!factory) {
            utils::log::error(std::format("Plugin [{}]: missing create_audit_sink_plugin symbol", config.path));
            return false;
        }

        auto* asp = factory();
        if (!asp) {
            utils::log::error(std::format("Plugin [{}]: factory returned null", config.path));
            return false;
        }

        const auto info = asp->get_info(asp->instance);
        if (info.api_version != SQLPROXY_PLUGIN_API_VERSION) {
            utils::log::error(std::format("Plugin [{}]: API version mismatch", config.path));
            if (asp->destroy) asp->destroy(asp->instance);
            delete asp;
            return false;
        }

        plugin->audit_sink = asp;
        utils::log::info(std::format("Plugin loaded: {} v{} (audit_sink)", info.name, info.version));

    } else {
        utils::log::error(std::format("Plugin [{}]: unknown type '{}'", config.path, config.type));
        return false;
    }

    std::unique_lock lock(mutex_);
    plugins_.emplace_back(std::move(plugin));
    rebuild_indexes();
    return true;
}

bool PluginRegistry::reload_plugin(const std::string& path) {
    // Find existing plugin to determine its type
    std::string type;
    {
        std::shared_lock lock(mutex_);
        for (const auto& p : plugins_) {
            if (p->path() == path) {
                type = p->type();
                break;
            }
        }
    }

    if (type.empty()) {
        utils::log::error(std::format("Plugin reload: no plugin loaded from '{}'", path));
        return false;
    }

    // Load the new version outside the lock
    void* new_handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!new_handle) {
        utils::log::error(std::format("Plugin reload failed [{}]: {}", path, dlerror()));
        return false;
    }

    auto new_plugin = std::make_unique<LoadedPlugin>(path, type, new_handle);

    if (type == "classifier") {
        using FactoryFn = ClassifierPlugin* (*)();
        const auto factory = reinterpret_cast<FactoryFn>(new_plugin->resolve("create_classifier_plugin"));
        if (!factory) {
            utils::log::error(std::format("Plugin reload [{}]: missing factory symbol", path));
            return false;
        }
        auto* cp = factory();
        if (!cp) {
            utils::log::error(std::format("Plugin reload [{}]: factory returned null", path));
            return false;
        }
        const auto info = cp->get_info(cp->instance);
        if (info.api_version != SQLPROXY_PLUGIN_API_VERSION) {
            utils::log::error(std::format("Plugin reload [{}]: API version mismatch", path));
            if (cp->destroy) cp->destroy(cp->instance);
            delete cp;
            return false;
        }
        new_plugin->classifier = cp;
        utils::log::info(std::format("Plugin reloaded: {} v{} (classifier)", info.name, info.version));

    } else if (type == "audit_sink") {
        using FactoryFn = AuditSinkPlugin* (*)();
        const auto factory = reinterpret_cast<FactoryFn>(new_plugin->resolve("create_audit_sink_plugin"));
        if (!factory) {
            utils::log::error(std::format("Plugin reload [{}]: missing factory symbol", path));
            return false;
        }
        auto* asp = factory();
        if (!asp) {
            utils::log::error(std::format("Plugin reload [{}]: factory returned null", path));
            return false;
        }
        const auto info = asp->get_info(asp->instance);
        if (info.api_version != SQLPROXY_PLUGIN_API_VERSION) {
            utils::log::error(std::format("Plugin reload [{}]: API version mismatch", path));
            if (asp->destroy) asp->destroy(asp->instance);
            delete asp;
            return false;
        }
        new_plugin->audit_sink = asp;
        utils::log::info(std::format("Plugin reloaded: {} v{} (audit_sink)", info.name, info.version));
    }

    // Swap under unique lock — old plugin destroyed after lock release
    std::unique_ptr<LoadedPlugin> old_plugin;
    {
        std::unique_lock lock(mutex_);
        for (auto& p : plugins_) {
            if (p->path() == path) {
                old_plugin = std::move(p);
                p = std::move(new_plugin);
                break;
            }
        }
        rebuild_indexes();
    }
    // old_plugin destroyed here (outside lock) — calls destroy + dlclose

    return true;
}

bool PluginRegistry::unload_plugin(const std::string& path) {
    std::unique_ptr<LoadedPlugin> removed;
    {
        std::unique_lock lock(mutex_);
        auto it = std::find_if(plugins_.begin(), plugins_.end(),
            [&path](const auto& p) { return p->path() == path; });
        if (it == plugins_.end()) {
            utils::log::warn(std::format("Plugin unload: '{}' not found", path));
            return false;
        }
        removed = std::move(*it);
        plugins_.erase(it);
        rebuild_indexes();
    }
    // removed destroyed here (outside lock)
    utils::log::info(std::format("Plugin unloaded: {}", path));
    return true;
}

std::vector<std::string> PluginRegistry::loaded_plugin_paths() const {
    std::shared_lock lock(mutex_);
    std::vector<std::string> paths;
    paths.reserve(plugins_.size());
    for (const auto& p : plugins_) {
        paths.push_back(p->path());
    }
    return paths;
}

void PluginRegistry::rebuild_indexes() {
    classifiers_.clear();
    audit_sinks_.clear();
    for (const auto& p : plugins_) {
        if (p->classifier) classifiers_.push_back(p->classifier);
        if (p->audit_sink) audit_sinks_.push_back(p->audit_sink);
    }
}

void PluginRegistry::unload_all() {
    std::unique_lock lock(mutex_);
    classifiers_.clear();
    audit_sinks_.clear();
    plugins_.clear();  // ~LoadedPlugin calls destroy + dlclose
}

} // namespace sqlproxy
