#include <catch2/catch_test_macros.hpp>
#include "server/dashboard_handler.hpp"
#include "server/dashboard_html.hpp"
#include "alerting/alert_evaluator.hpp"
#include "alerting/alert_types.hpp"

#include <string>
#include <string_view>

using namespace sqlproxy;

// ============================================================================
// Dashboard HTML Tests
// ============================================================================

TEST_CASE("Dashboard: HTML content is non-empty", "[dashboard]") {
    REQUIRE(kDashboardHtml != nullptr);
    std::string_view html(kDashboardHtml);
    REQUIRE(html.size() > 100);
}

TEST_CASE("Dashboard: HTML contains DOCTYPE", "[dashboard]") {
    std::string_view html(kDashboardHtml);
    REQUIRE(html.find("<!DOCTYPE html>") != std::string_view::npos);
}

TEST_CASE("Dashboard: HTML contains Chart.js CDN", "[dashboard]") {
    std::string_view html(kDashboardHtml);
    REQUIRE(html.find("chart.js") != std::string_view::npos);
}

TEST_CASE("Dashboard: HTML contains SSE EventSource", "[dashboard]") {
    std::string_view html(kDashboardHtml);
    REQUIRE(html.find("EventSource") != std::string_view::npos);
}

TEST_CASE("Dashboard: HTML contains metrics stream URL", "[dashboard]") {
    std::string_view html(kDashboardHtml);
    REQUIRE(html.find("/dashboard/api/metrics/stream") != std::string_view::npos);
}

TEST_CASE("Dashboard: HTML contains dashboard API URLs", "[dashboard]") {
    std::string_view html(kDashboardHtml);
    REQUIRE(html.find("/dashboard/api/policies") != std::string_view::npos);
    REQUIRE(html.find("/dashboard/api/alerts") != std::string_view::npos);
    REQUIRE(html.find("/dashboard/api/users") != std::string_view::npos);
}

TEST_CASE("Dashboard: DashboardHandler construction", "[dashboard]") {
    // Just verify it constructs without crashing (no pipeline needed for construction)
    auto handler = std::make_shared<DashboardHandler>(nullptr, nullptr);
    REQUIRE(handler != nullptr);
}
