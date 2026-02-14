#include <catch2/catch_test_macros.hpp>
#include "core/llm_client.hpp"
#include <thread>
#include <chrono>

using namespace sqlproxy;

static LlmClient::Config enabled_config() {
    LlmClient::Config cfg;
    cfg.enabled = true;
    cfg.endpoint = "http://localhost:11434";
    cfg.api_key = "test-key";
    cfg.default_model = "gpt-4";
    cfg.timeout_ms = 5000;
    cfg.max_retries = 1;
    cfg.max_requests_per_minute = 60;
    cfg.cache_enabled = true;
    cfg.cache_max_entries = 100;
    cfg.cache_ttl_seconds = 3600;
    return cfg;
}

TEST_CASE("LlmClient", "[llm_client]") {

    SECTION("Disabled returns error") {
        LlmClient client;
        REQUIRE_FALSE(client.is_enabled());

        LlmRequest req;
        req.use_case = LlmUseCase::POLICY_GENERATOR;
        req.prompt = "test";
        auto resp = client.complete(req);
        REQUIRE_FALSE(resp.success);
        REQUIRE(resp.error.find("disabled") != std::string::npos);
    }

    SECTION("Enabled with config") {
        LlmClient client(enabled_config());
        REQUIRE(client.is_enabled());
    }

    SECTION("API call to unreachable endpoint returns error") {
        auto cfg = enabled_config();
        cfg.max_retries = 0;
        cfg.timeout_ms = 1000;
        LlmClient client(cfg);

        LlmRequest req;
        req.use_case = LlmUseCase::POLICY_GENERATOR;
        req.prompt = "SELECT * FROM users";
        req.context = "test context";

        auto resp1 = client.complete(req);
        // With a real HTTP client calling a non-existent endpoint, this fails
        REQUIRE_FALSE(resp1.success);
        REQUIRE_FALSE(resp1.from_cache);
        REQUIRE(resp1.error.find("connection error") != std::string::npos);

        auto stats = client.get_stats();
        REQUIRE(stats.total_requests == 1);
        REQUIRE(stats.api_calls == 1);
        REQUIRE(stats.api_errors == 1);
    }

    SECTION("Cache key uniqueness — different use cases") {
        auto key1 = LlmClient::cache_key(LlmUseCase::POLICY_GENERATOR, "same input");
        auto key2 = LlmClient::cache_key(LlmUseCase::ANOMALY_EXPLANATION, "same input");
        REQUIRE(key1 != key2);
    }

    SECTION("Cache key uniqueness — different inputs") {
        auto key1 = LlmClient::cache_key(LlmUseCase::POLICY_GENERATOR, "input A");
        auto key2 = LlmClient::cache_key(LlmUseCase::POLICY_GENERATOR, "input B");
        REQUIRE(key1 != key2);
    }

    SECTION("Rate limiting") {
        auto cfg = enabled_config();
        cfg.max_requests_per_minute = 3;
        cfg.max_retries = 0;
        cfg.timeout_ms = 1000;
        LlmClient client(cfg);

        LlmRequest req;
        req.use_case = LlmUseCase::POLICY_GENERATOR;

        // First 3 pass rate limit check (but API call fails — unreachable)
        req.prompt = "query 1";
        client.complete(req);  // fails at API level, but passes rate limit
        req.prompt = "query 2";
        client.complete(req);
        req.prompt = "query 3";
        client.complete(req);

        // 4th should be rate limited before even trying the API
        req.prompt = "query 4";
        auto resp = client.complete(req);
        REQUIRE_FALSE(resp.success);
        REQUIRE(resp.error.find("Rate limited") != std::string::npos);

        auto stats = client.get_stats();
        REQUIRE(stats.rate_limited == 1);
    }

    SECTION("System prompt selection per use case") {
        auto p1 = LlmClient::get_system_prompt(LlmUseCase::POLICY_GENERATOR);
        auto p2 = LlmClient::get_system_prompt(LlmUseCase::ANOMALY_EXPLANATION);
        auto p3 = LlmClient::get_system_prompt(LlmUseCase::NL_TO_POLICY);
        auto p4 = LlmClient::get_system_prompt(LlmUseCase::SQL_INTENT_CLASSIFICATION);

        REQUIRE(p1 != p2);
        REQUIRE(p2 != p3);
        REQUIRE(p3 != p4);

        REQUIRE(p1.find("policy") != std::string::npos);
        REQUIRE(p2.find("anomaly") != std::string::npos);
        REQUIRE(p3.find("TOML") != std::string::npos);
        REQUIRE(p4.find("Classify") != std::string::npos);
    }

    SECTION("Convenience methods call complete()") {
        auto cfg = enabled_config();
        cfg.max_retries = 0;
        cfg.timeout_ms = 1000;
        LlmClient client(cfg);

        // All convenience methods should go through complete()
        // They will fail at API level (unreachable endpoint) but exercise the code path
        auto r1 = client.generate_policy("SELECT * FROM users", "admin context");
        REQUIRE_FALSE(r1.success);  // API unreachable

        auto r2 = client.explain_anomaly("User accessed PII at 3am");
        REQUIRE_FALSE(r2.success);

        auto r3 = client.nl_to_policy("Block all access to salary column");
        REQUIRE_FALSE(r3.success);

        auto r4 = client.classify_intent("SELECT * FROM users; DROP TABLE users;--");
        REQUIRE_FALSE(r4.success);

        auto r5 = client.nl_to_sql("Show all customers", "customers (id integer, name text)");
        REQUIRE_FALSE(r5.success);

        auto stats = client.get_stats();
        REQUIRE(stats.total_requests == 5);
        REQUIRE(stats.api_calls == 5);
    }

    SECTION("No API key returns error") {
        auto cfg = enabled_config();
        cfg.api_key = "";
        cfg.cache_enabled = false;
        LlmClient client(cfg);

        LlmRequest req;
        req.use_case = LlmUseCase::POLICY_GENERATOR;
        req.prompt = "test";
        auto resp = client.complete(req);
        REQUIRE_FALSE(resp.success);
        REQUIRE(resp.error.find("API key") != std::string::npos);
    }

    SECTION("Use case to string") {
        REQUIRE(std::string(llm_use_case_to_string(LlmUseCase::POLICY_GENERATOR)) == "policy_generator");
        REQUIRE(std::string(llm_use_case_to_string(LlmUseCase::ANOMALY_EXPLANATION)) == "anomaly_explanation");
        REQUIRE(std::string(llm_use_case_to_string(LlmUseCase::NL_TO_POLICY)) == "nl_to_policy");
        REQUIRE(std::string(llm_use_case_to_string(LlmUseCase::SQL_INTENT_CLASSIFICATION)) == "sql_intent_classification");
        REQUIRE(std::string(llm_use_case_to_string(LlmUseCase::NL_TO_SQL)) == "nl_to_sql");
    }

    SECTION("NL_TO_SQL system prompt") {
        auto prompt = LlmClient::get_system_prompt(LlmUseCase::NL_TO_SQL);
        REQUIRE(prompt.find("PostgreSQL") != std::string::npos);
        REQUIRE(prompt.find("SELECT") != std::string::npos);
    }
}
