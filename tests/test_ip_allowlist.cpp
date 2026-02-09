#include <catch2/catch_test_macros.hpp>
#include "security/ip_allowlist.hpp"

using namespace sqlproxy;

TEST_CASE("IpAllowlist: empty allowlist allows all IPs", "[ip_allowlist]") {
    std::vector<std::string> allowlist;
    CHECK(IpAllowlist::is_allowed("10.0.0.1", allowlist));
    CHECK(IpAllowlist::is_allowed("192.168.1.100", allowlist));
    CHECK(IpAllowlist::is_allowed("8.8.8.8", allowlist));
}

TEST_CASE("IpAllowlist: exact IP match allows access", "[ip_allowlist]") {
    std::vector<std::string> allowlist = {"192.168.1.100"};
    CHECK(IpAllowlist::is_allowed("192.168.1.100", allowlist));
    CHECK_FALSE(IpAllowlist::is_allowed("192.168.1.101", allowlist));
    CHECK_FALSE(IpAllowlist::is_allowed("10.0.0.1", allowlist));
}

TEST_CASE("IpAllowlist: CIDR /8 range matches", "[ip_allowlist]") {
    std::vector<std::string> allowlist = {"10.0.0.0/8"};
    CHECK(IpAllowlist::is_allowed("10.0.0.1", allowlist));
    CHECK(IpAllowlist::is_allowed("10.255.255.255", allowlist));
    CHECK(IpAllowlist::is_allowed("10.1.2.3", allowlist));
    CHECK_FALSE(IpAllowlist::is_allowed("11.0.0.1", allowlist));
    CHECK_FALSE(IpAllowlist::is_allowed("192.168.1.1", allowlist));
}

TEST_CASE("IpAllowlist: CIDR /24 range rejects out-of-range IP", "[ip_allowlist]") {
    std::vector<std::string> allowlist = {"192.168.1.0/24"};
    CHECK(IpAllowlist::is_allowed("192.168.1.1", allowlist));
    CHECK(IpAllowlist::is_allowed("192.168.1.254", allowlist));
    CHECK_FALSE(IpAllowlist::is_allowed("192.168.2.1", allowlist));
    CHECK_FALSE(IpAllowlist::is_allowed("192.168.0.1", allowlist));
}

TEST_CASE("IpAllowlist: multiple entries with mixed CIDR", "[ip_allowlist]") {
    std::vector<std::string> allowlist = {
        "10.0.0.0/8",
        "192.168.1.100",
        "172.16.0.0/12"
    };
    CHECK(IpAllowlist::is_allowed("10.5.5.5", allowlist));
    CHECK(IpAllowlist::is_allowed("192.168.1.100", allowlist));
    CHECK(IpAllowlist::is_allowed("172.16.0.1", allowlist));
    CHECK(IpAllowlist::is_allowed("172.31.255.255", allowlist));
    CHECK_FALSE(IpAllowlist::is_allowed("192.168.1.101", allowlist));
    CHECK_FALSE(IpAllowlist::is_allowed("8.8.8.8", allowlist));
}

TEST_CASE("IpAllowlist: invalid IP is rejected", "[ip_allowlist]") {
    std::vector<std::string> allowlist = {"10.0.0.0/8"};
    CHECK_FALSE(IpAllowlist::is_allowed("not-an-ip", allowlist));
    CHECK_FALSE(IpAllowlist::is_allowed("", allowlist));
}
