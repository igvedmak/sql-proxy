#pragma once

#include "plugin/plugin_interface.hpp"
#include <string>
#include <vector>

namespace sqlproxy::test {

// In-process mock classifier plugin (no dlopen needed for unit tests)
class MockClassifierPlugin {
public:
    static PluginInfo get_info(void* /*instance*/) {
        return PluginInfo{"mock_classifier", "1.0.0", "classifier", SQLPROXY_PLUGIN_API_VERSION};
    }

    static ClassifierPluginResult classify_column(void* instance,
                                                   const char* column_name,
                                                   const char** /*values*/,
                                                   size_t /*value_count*/) {
        auto* self = static_cast<MockClassifierPlugin*>(instance);
        self->calls.push_back(column_name);

        // Match configured patterns
        std::string col(column_name);
        for (const auto& [pattern, result] : self->patterns) {
            if (col.find(pattern) != std::string::npos) {
                return result;
            }
        }
        return ClassifierPluginResult{nullptr, 0.0};
    }

    static void destroy(void* instance) {
        delete static_cast<MockClassifierPlugin*>(instance);
    }

    static ClassifierPlugin* create() {
        auto* self = new MockClassifierPlugin();
        auto* plugin = new ClassifierPlugin{};
        plugin->instance = self;
        plugin->get_info = get_info;
        plugin->classify_column = classify_column;
        plugin->destroy = destroy;
        return plugin;
    }

    // Test configuration
    std::vector<std::pair<std::string, ClassifierPluginResult>> patterns;
    std::vector<std::string> calls;
};

// In-process mock audit sink plugin
class MockAuditSinkPlugin {
public:
    static PluginInfo get_info(void* /*instance*/) {
        return PluginInfo{"mock_audit_sink", "1.0.0", "audit_sink", SQLPROXY_PLUGIN_API_VERSION};
    }

    static int emit(void* instance, const char* json_record, size_t json_len) {
        auto* self = static_cast<MockAuditSinkPlugin*>(instance);
        self->records.emplace_back(json_record, json_len);
        return 0;
    }

    static void flush(void* instance) {
        auto* self = static_cast<MockAuditSinkPlugin*>(instance);
        ++self->flush_count;
    }

    static void destroy(void* instance) {
        delete static_cast<MockAuditSinkPlugin*>(instance);
    }

    static AuditSinkPlugin* create() {
        auto* self = new MockAuditSinkPlugin();
        auto* plugin = new AuditSinkPlugin{};
        plugin->instance = self;
        plugin->get_info = get_info;
        plugin->emit = emit;
        plugin->flush = flush;
        plugin->destroy = destroy;
        return plugin;
    }

    // Test inspection
    std::vector<std::string> records;
    int flush_count = 0;
};

} // namespace sqlproxy::test
