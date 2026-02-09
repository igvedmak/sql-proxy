#pragma once

#include "auth/iauth_provider.hpp"
#include <memory>
#include <vector>

namespace sqlproxy {

/**
 * @brief Ordered chain of authentication providers
 *
 * Tries each provider in order until one succeeds.
 * Stops at first successful authentication.
 */
class AuthChain {
public:
    void add_provider(std::shared_ptr<IAuthProvider> provider);

    /**
     * @brief Try all providers in order
     * @return First successful AuthResult, or failure with combined errors
     */
    [[nodiscard]] IAuthProvider::AuthResult authenticate(
        const std::string& auth_header,
        const std::string& body_user) const;

    [[nodiscard]] size_t provider_count() const { return providers_.size(); }

private:
    std::vector<std::shared_ptr<IAuthProvider>> providers_;
};

} // namespace sqlproxy
