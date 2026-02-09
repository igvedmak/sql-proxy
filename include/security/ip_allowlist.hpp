#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace sqlproxy {

class IpAllowlist {
public:
    struct CidrRange {
        uint32_t network = 0;
        uint32_t mask = 0;
    };

    static bool parse_ip(std::string_view ip, uint32_t& out);
    static bool parse_cidr(std::string_view cidr, CidrRange& out);
    static bool ip_matches_cidr(uint32_t ip, const CidrRange& range);

    /**
     * @brief Check if IP is allowed by the given allowlist
     * @param ip Client IP address (e.g., "10.0.1.5")
     * @param allowlist CIDR entries (e.g., "10.0.0.0/8", "192.168.1.100")
     * @return true if allowlist is empty or IP matches any entry
     */
    [[nodiscard]] static bool is_allowed(std::string_view ip,
                                          const std::vector<std::string>& allowlist);
};

} // namespace sqlproxy
