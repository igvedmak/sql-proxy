#include <catch2/catch_test_macros.hpp>
#include "plugin/plugin_interface.hpp"
#include "plugin/plugin_loader.hpp"
#include "mocks/mock_plugin.hpp"

using namespace sqlproxy;

TEST_CASE("Plugin interface: API version constant", "[plugin]") {
    REQUIRE(SQLPROXY_PLUGIN_API_VERSION == 1);
}

TEST_CASE("Plugin interface: PluginInfo fields", "[plugin]") {
    PluginInfo info{"test_plugin", "1.0.0", "classifier", SQLPROXY_PLUGIN_API_VERSION};
    REQUIRE(std::string(info.name) == "test_plugin");
    REQUIRE(std::string(info.version) == "1.0.0");
    REQUIRE(std::string(info.type) == "classifier");
    REQUIRE(info.api_version == 1);
}

TEST_CASE("MockClassifierPlugin: create and get_info", "[plugin]") {
    auto* plugin = test::MockClassifierPlugin::create();
    REQUIRE(plugin != nullptr);
    REQUIRE(plugin->instance != nullptr);

    auto info = plugin->get_info(plugin->instance);
    REQUIRE(std::string(info.name) == "mock_classifier");
    REQUIRE(std::string(info.version) == "1.0.0");
    REQUIRE(std::string(info.type) == "classifier");
    REQUIRE(info.api_version == SQLPROXY_PLUGIN_API_VERSION);

    // Clean up
    plugin->destroy(plugin->instance);
    delete plugin;
}

TEST_CASE("MockClassifierPlugin: classify with patterns", "[plugin]") {
    auto* plugin = test::MockClassifierPlugin::create();
    auto* self = static_cast<test::MockClassifierPlugin*>(plugin->instance);

    // Configure patterns
    self->patterns.push_back({"email", ClassifierPluginResult{"PII.Email", 0.95}});
    self->patterns.push_back({"ssn", ClassifierPluginResult{"PII.SSN", 0.99}});

    // Classify matching column
    auto result = plugin->classify_column(plugin->instance, "user_email", nullptr, 0);
    REQUIRE(std::string(result.classification) == "PII.Email");
    REQUIRE(result.confidence > 0.9);

    // Classify SSN column
    result = plugin->classify_column(plugin->instance, "ssn_number", nullptr, 0);
    REQUIRE(std::string(result.classification) == "PII.SSN");

    // Non-matching column
    result = plugin->classify_column(plugin->instance, "id", nullptr, 0);
    REQUIRE(result.classification == nullptr);
    REQUIRE(result.confidence == 0.0);

    // Verify call tracking
    REQUIRE(self->calls.size() == 3);
    REQUIRE(self->calls[0] == "user_email");
    REQUIRE(self->calls[1] == "ssn_number");
    REQUIRE(self->calls[2] == "id");

    plugin->destroy(plugin->instance);
    delete plugin;
}

TEST_CASE("MockAuditSinkPlugin: create and emit", "[plugin]") {
    auto* plugin = test::MockAuditSinkPlugin::create();
    auto* self = static_cast<test::MockAuditSinkPlugin*>(plugin->instance);

    REQUIRE(self->records.empty());
    REQUIRE(self->flush_count == 0);

    // Emit records
    std::string record1 = R"({"event":"query","user":"alice"})";
    std::string record2 = R"({"event":"query","user":"bob"})";
    plugin->emit(plugin->instance, record1.c_str(), record1.size());
    plugin->emit(plugin->instance, record2.c_str(), record2.size());

    REQUIRE(self->records.size() == 2);
    REQUIRE(self->records[0] == record1);
    REQUIRE(self->records[1] == record2);

    // Flush
    plugin->flush(plugin->instance);
    REQUIRE(self->flush_count == 1);

    plugin->flush(plugin->instance);
    REQUIRE(self->flush_count == 2);

    plugin->destroy(plugin->instance);
    delete plugin;
}

TEST_CASE("PluginRegistry: initial state", "[plugin]") {
    PluginRegistry registry;
    REQUIRE(registry.plugin_count() == 0);
    REQUIRE(registry.classifier_plugins().empty());
    REQUIRE(registry.audit_sink_plugins().empty());
}

TEST_CASE("PluginRegistry: load nonexistent plugin returns false", "[plugin]") {
    PluginRegistry registry;

    PluginConfig config;
    config.path = "/nonexistent/path/plugin.so";
    config.type = "classifier";

    bool loaded = registry.load_plugin(config);
    REQUIRE_FALSE(loaded);
    REQUIRE(registry.plugin_count() == 0);
}

TEST_CASE("PluginRegistry: unload_all on empty registry", "[plugin]") {
    PluginRegistry registry;
    registry.unload_all(); // Should not crash
    REQUIRE(registry.plugin_count() == 0);
}

TEST_CASE("ClassifierPluginResult: zero-init", "[plugin]") {
    ClassifierPluginResult result{nullptr, 0.0};
    REQUIRE(result.classification == nullptr);
    REQUIRE(result.confidence == 0.0);
}
