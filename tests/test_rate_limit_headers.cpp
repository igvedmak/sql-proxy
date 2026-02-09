#include <catch2/catch_test_macros.hpp>
#include "core/types.hpp"
#include "core/request_context.hpp"

using namespace sqlproxy;

TEST_CASE("RateLimitHeaders: RateLimitResult stored in RequestContext", "[rate_limit][headers]") {
    RequestContext ctx;

    // Simulate rate limiter populating the result
    RateLimitResult result(true, 42, std::chrono::milliseconds(0), "global");
    ctx.rate_limit_result = result;

    CHECK(ctx.rate_limit_result.allowed == true);
    CHECK(ctx.rate_limit_result.tokens_remaining == 42);
    CHECK(ctx.rate_limit_result.level == "global");
}

TEST_CASE("RateLimitHeaders: result propagated to ProxyResponse", "[rate_limit][headers]") {
    ProxyResponse response;

    RateLimitResult rl(true, 100, std::chrono::milliseconds(0), "user");
    response.rate_limit_info = rl;

    CHECK(response.rate_limit_info.allowed == true);
    CHECK(response.rate_limit_info.tokens_remaining == 100);
    CHECK(response.rate_limit_info.level == "user");
}

TEST_CASE("RateLimitHeaders: Retry-After conversion ms to seconds", "[rate_limit][headers]") {
    RateLimitResult result(false, 0, std::chrono::milliseconds(3500), "global");

    // Retry-After = ms / 1000, min 1
    auto retry_seconds = result.retry_after.count() / 1000;
    if (retry_seconds < 1) retry_seconds = 1;

    CHECK(retry_seconds == 3);

    // Edge case: less than 1 second → clamped to 1
    RateLimitResult short_wait(false, 0, std::chrono::milliseconds(200), "user");
    auto short_retry = short_wait.retry_after.count() / 1000;
    if (short_retry < 1) short_retry = 1;
    CHECK(short_retry == 1);
}

TEST_CASE("RateLimitHeaders: denied result has zero tokens", "[rate_limit][headers]") {
    RateLimitResult denied(false, 0, std::chrono::milliseconds(5000), "user_db");

    CHECK_FALSE(denied.allowed);
    CHECK(denied.tokens_remaining == 0);
    CHECK(denied.retry_after.count() == 5000);
    CHECK(denied.level == "user_db");
}
