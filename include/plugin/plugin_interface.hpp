#pragma once

#include <cstddef>
#include <cstdint>

// C ABI plugin interfaces for dynamic loading via dlopen/dlsym.
// Plugins implement these structs and export a factory function.

extern "C" {

// Plugin metadata
struct PluginInfo {
    const char* name;
    const char* version;
    const char* type;       // "classifier" or "audit_sink"
    uint32_t api_version;   // Must match SQLPROXY_PLUGIN_API_VERSION
};

constexpr uint32_t SQLPROXY_PLUGIN_API_VERSION = 1;

// Classification result from a plugin classifier
struct ClassifierPluginResult {
    const char* classification;   // e.g. "PII.CustomSSN" (null = no match)
    double confidence;            // 0.0 - 1.0
};

// Classifier plugin vtable
struct ClassifierPlugin {
    void* instance;
    PluginInfo (*get_info)(void* instance);
    ClassifierPluginResult (*classify_column)(void* instance, const char* column_name,
                                              const char** values, size_t value_count);
    void (*destroy)(void* instance);
};

// Audit sink plugin vtable
struct AuditSinkPlugin {
    void* instance;
    PluginInfo (*get_info)(void* instance);
    int (*emit)(void* instance, const char* json_record, size_t json_len);   // 0 = success
    void (*flush)(void* instance);
    void (*destroy)(void* instance);
};

// Factory function signatures (plugins export these)
// "create_classifier_plugin" -> ClassifierPlugin*
// "create_audit_sink_plugin" -> AuditSinkPlugin*

} // extern "C"
