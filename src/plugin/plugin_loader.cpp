#include "plugin/plugin_loader.hpp"
#include "core/utils.hpp"

#include <dlfcn.h>
#include <format>

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
        auto factory = reinterpret_cast<FactoryFn>(plugin->resolve("create_classifier_plugin"));
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
        auto info = cp->get_info(cp->instance);
        if (info.api_version != SQLPROXY_PLUGIN_API_VERSION) {
            utils::log::error(std::format("Plugin [{}]: API version mismatch (got {}, expected {})",
                config.path, info.api_version, SQLPROXY_PLUGIN_API_VERSION));
            if (cp->destroy) cp->destroy(cp->instance);
            delete cp;
            return false;
        }

        plugin->classifier = cp;
        classifiers_.push_back(cp);
        utils::log::info(std::format("Plugin loaded: {} v{} (classifier)", info.name, info.version));

    } else if (config.type == "audit_sink") {
        // Resolve factory: AuditSinkPlugin* create_audit_sink_plugin()
        using FactoryFn = AuditSinkPlugin* (*)();
        auto factory = reinterpret_cast<FactoryFn>(plugin->resolve("create_audit_sink_plugin"));
        if (!factory) {
            utils::log::error(std::format("Plugin [{}]: missing create_audit_sink_plugin symbol", config.path));
            return false;
        }

        auto* asp = factory();
        if (!asp) {
            utils::log::error(std::format("Plugin [{}]: factory returned null", config.path));
            return false;
        }

        auto info = asp->get_info(asp->instance);
        if (info.api_version != SQLPROXY_PLUGIN_API_VERSION) {
            utils::log::error(std::format("Plugin [{}]: API version mismatch", config.path));
            if (asp->destroy) asp->destroy(asp->instance);
            delete asp;
            return false;
        }

        plugin->audit_sink = asp;
        audit_sinks_.push_back(asp);
        utils::log::info(std::format("Plugin loaded: {} v{} (audit_sink)", info.name, info.version));

    } else {
        utils::log::error(std::format("Plugin [{}]: unknown type '{}'", config.path, config.type));
        return false;
    }

    plugins_.push_back(std::move(plugin));
    return true;
}

void PluginRegistry::unload_all() {
    classifiers_.clear();
    audit_sinks_.clear();
    plugins_.clear();  // ~LoadedPlugin calls destroy + dlclose
}

} // namespace sqlproxy
