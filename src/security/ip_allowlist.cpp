#include "security/ip_allowlist.hpp"

namespace sqlproxy {

bool IpAllowlist::parse_ip(std::string_view ip, uint32_t& out) {
    uint32_t octets[4]{};
    size_t octet_idx = 0;
    uint32_t val = 0;
    bool has_digit = false;

    for (size_t i = 0; i <= ip.size(); ++i) {
        if (i == ip.size() || ip[i] == '.') {
            if (!has_digit || val > 255 || octet_idx > 3) return false;
            octets[octet_idx++] = val;
            val = 0;
            has_digit = false;
        } else if (ip[i] >= '0' && ip[i] <= '9') {
            val = val * 10 + static_cast<uint32_t>(ip[i] - '0');
            has_digit = true;
        } else {
            return false;
        }
    }
    if (octet_idx != 4) return false;
    out = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    return true;
}

bool IpAllowlist::parse_cidr(std::string_view cidr, CidrRange& out) {
    const auto slash = cidr.find('/');
    if (slash == std::string_view::npos) {
        // No prefix → /32 (exact match)
        if (!parse_ip(cidr, out.network)) return false;
        out.mask = 0xFFFFFFFFu;
        return true;
    }

    if (!parse_ip(cidr.substr(0, slash), out.network)) return false;

    // Parse prefix length
    uint32_t prefix = 0;
    for (size_t i = slash + 1; i < cidr.size(); ++i) {
        if (cidr[i] < '0' || cidr[i] > '9') return false;
        prefix = prefix * 10 + static_cast<uint32_t>(cidr[i] - '0');
    }
    if (prefix > 32) return false;
    out.mask = (prefix == 0) ? 0u : ~((1u << (32 - prefix)) - 1);
    out.network &= out.mask;  // normalize
    return true;
}

bool IpAllowlist::ip_matches_cidr(uint32_t ip, const CidrRange& range) {
    return (ip & range.mask) == range.network;
}

bool IpAllowlist::is_allowed(std::string_view ip,
                              const std::vector<std::string>& allowlist) {
    if (allowlist.empty()) return true;

    uint32_t client_ip = 0;
    if (!parse_ip(ip, client_ip)) return false;

    for (const auto& entry : allowlist) {
        CidrRange range;
        if (parse_cidr(entry, range) && ip_matches_cidr(client_ip, range)) {
            return true;
        }
    }
    return false;
}

} // namespace sqlproxy
