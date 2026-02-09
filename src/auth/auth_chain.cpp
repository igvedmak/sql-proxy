#include "auth/auth_chain.hpp"

namespace sqlproxy {

void AuthChain::add_provider(std::shared_ptr<IAuthProvider> provider) {
    providers_.push_back(std::move(provider));
}

IAuthProvider::AuthResult AuthChain::authenticate(
    const std::string& auth_header,
    const std::string& body_user) const {

    std::string combined_errors;

    for (const auto& provider : providers_) {
        const auto result = provider->authenticate(auth_header, body_user);
        if (result.authenticated) {
            return result;
        }
        if (!result.error.empty()) {
            if (!combined_errors.empty()) combined_errors += "; ";
            combined_errors += provider->name() + ": " + result.error;
        }
    }

    IAuthProvider::AuthResult failure;
    failure.error = combined_errors.empty()
        ? "No authentication provider succeeded"
        : combined_errors;
    return failure;
}

} // namespace sqlproxy
