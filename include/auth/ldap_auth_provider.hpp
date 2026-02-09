#pragma once

#include "auth/iauth_provider.hpp"
#include <string>

namespace sqlproxy {

struct LdapConfig {
    std::string url;                                  // e.g., "ldap://ldap.example.com:389"
    std::string base_dn;                              // e.g., "dc=example,dc=com"
    std::string bind_dn;                              // Admin bind DN for searches
    std::string bind_password;                        // Admin bind password
    std::string user_filter = "(uid={})";             // {} replaced with username
    std::string group_attribute = "memberOf";          // Attribute for group membership
};

/**
 * @brief LDAP authentication provider
 *
 * Authenticates via LDAP simple bind. Extracts group memberships as roles.
 * Requires libldap (compile with ENABLE_LDAP=ON).
 */
class LdapAuthProvider : public IAuthProvider {
public:
    explicit LdapAuthProvider(LdapConfig config);

    [[nodiscard]] AuthResult authenticate(
        const std::string& auth_header,
        const std::string& body_user) override;

    [[nodiscard]] std::string name() const override { return "ldap"; }

private:
    static std::pair<std::string, std::string> decode_basic_auth(const std::string& auth_header);

    LdapConfig config_;
};

} // namespace sqlproxy
