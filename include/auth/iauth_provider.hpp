#pragma once

#include <string>
#include <unordered_map>
#include <vector>

namespace sqlproxy {

/**
 * @brief Interface for authentication providers
 *
 * Each provider implements a different auth mechanism (API key, JWT, LDAP).
 * AuthChain tries providers in order until one succeeds.
 */
class IAuthProvider {
public:
    struct AuthResult {
        bool authenticated = false;
        std::string user;
        std::vector<std::string> roles;
        std::unordered_map<std::string, std::string> attributes;
        std::string error;
    };

    virtual ~IAuthProvider() = default;

    /**
     * @brief Attempt to authenticate from request headers/body
     * @param auth_header The Authorization header value (may be empty)
     * @param body_user The "user" field from the JSON body (may be empty)
     * @return AuthResult with authentication status
     */
    [[nodiscard]] virtual AuthResult authenticate(
        const std::string& auth_header,
        const std::string& body_user) = 0;

    [[nodiscard]] virtual std::string name() const = 0;
};

} // namespace sqlproxy
