#include <catch2/catch_test_macros.hpp>
#include "server/shutdown_coordinator.hpp"
#include "config/config_loader.hpp"

#include <thread>
#include <vector>
#include <atomic>

using namespace sqlproxy;

TEST_CASE("ShutdownCoordinator: try_enter succeeds before shutdown", "[shutdown]") {
    ShutdownCoordinator sc;
    CHECK(sc.try_enter_request());
    CHECK(sc.in_flight_count() == 1);
    sc.leave_request();
    CHECK(sc.in_flight_count() == 0);
}

TEST_CASE("ShutdownCoordinator: try_enter fails after shutdown", "[shutdown]") {
    ShutdownCoordinator sc;
    sc.initiate_shutdown();
    CHECK_FALSE(sc.try_enter_request());
    CHECK(sc.is_shutting_down());
}

TEST_CASE("ShutdownCoordinator: wait_for_drain returns immediately when no in-flight", "[shutdown]") {
    ShutdownCoordinator::Config cfg;
    cfg.shutdown_timeout = std::chrono::milliseconds(100);
    ShutdownCoordinator sc(cfg);

    sc.initiate_shutdown();
    auto start = std::chrono::steady_clock::now();
    bool ok = sc.wait_for_drain();
    auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(ok);
    CHECK(elapsed < std::chrono::milliseconds(50));
}

TEST_CASE("ShutdownCoordinator: wait_for_drain blocks until leave_request", "[shutdown]") {
    ShutdownCoordinator::Config cfg;
    cfg.shutdown_timeout = std::chrono::milliseconds(5000);
    ShutdownCoordinator sc(cfg);

    // Simulate in-flight request
    REQUIRE(sc.try_enter_request());

    // Shutdown in background thread
    std::atomic<bool> drained{false};
    std::thread drain_thread([&] {
        sc.initiate_shutdown();
        drained = sc.wait_for_drain();
    });

    // Give the drain thread time to start waiting
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    CHECK_FALSE(drained.load());

    // Complete the in-flight request
    sc.leave_request();

    drain_thread.join();
    CHECK(drained.load());
}

TEST_CASE("ShutdownCoordinator: timeout works", "[shutdown]") {
    ShutdownCoordinator::Config cfg;
    cfg.shutdown_timeout = std::chrono::milliseconds(50);
    ShutdownCoordinator sc(cfg);

    // Start a request but never finish it
    REQUIRE(sc.try_enter_request());
    sc.initiate_shutdown();

    auto start = std::chrono::steady_clock::now();
    bool ok = sc.wait_for_drain();
    auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK_FALSE(ok);  // Timed out
    CHECK(elapsed >= std::chrono::milliseconds(40));  // Waited for timeout
    CHECK(sc.in_flight_count() == 1);  // Still has in-flight

    // Cleanup
    sc.leave_request();
}

TEST_CASE("ShutdownCoordinator: concurrent enter/leave/shutdown", "[shutdown]") {
    ShutdownCoordinator::Config cfg;
    cfg.shutdown_timeout = std::chrono::milliseconds(2000);
    ShutdownCoordinator sc(cfg);

    std::atomic<int> entered{0};
    std::atomic<int> rejected{0};
    std::vector<std::thread> threads;

    // Launch concurrent requests
    for (int i = 0; i < 20; ++i) {
        threads.emplace_back([&] {
            if (sc.try_enter_request()) {
                entered.fetch_add(1);
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                sc.leave_request();
            } else {
                rejected.fetch_add(1);
            }
        });
    }

    // Initiate shutdown partway through
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    sc.initiate_shutdown();

    for (auto& t : threads) t.join();

    bool drained = sc.wait_for_drain();
    CHECK(drained);
    CHECK(sc.in_flight_count() == 0);
    CHECK((entered.load() + rejected.load()) == 20);
}

TEST_CASE("ShutdownCoordinator: in_flight_count tracking", "[shutdown]") {
    ShutdownCoordinator sc;

    CHECK(sc.in_flight_count() == 0);
    sc.try_enter_request();
    CHECK(sc.in_flight_count() == 1);
    sc.try_enter_request();
    CHECK(sc.in_flight_count() == 2);
    sc.leave_request();
    CHECK(sc.in_flight_count() == 1);
    sc.leave_request();
    CHECK(sc.in_flight_count() == 0);
}

TEST_CASE("ShutdownCoordinator: double-check prevents race", "[shutdown]") {
    ShutdownCoordinator sc;

    // Enter a request
    REQUIRE(sc.try_enter_request());

    // Shutdown while request is in-flight
    sc.initiate_shutdown();

    // New requests should be rejected
    CHECK_FALSE(sc.try_enter_request());

    // But existing request can still complete
    CHECK(sc.in_flight_count() == 1);
    sc.leave_request();
    CHECK(sc.in_flight_count() == 0);
}

TEST_CASE("ShutdownCoordinator: config from TOML", "[shutdown][config]") {
    std::string toml = R"(
[server]
shutdown_timeout_ms = 15000
)";

    auto result = ConfigLoader::load_from_string(toml);
    REQUIRE(result.success);
    REQUIRE(result.config.server.shutdown_timeout_ms == 15000);
}
