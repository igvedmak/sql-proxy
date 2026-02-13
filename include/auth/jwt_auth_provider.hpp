#pragma once

#include "auth/iauth_provider.hpp"
#include <string>

namespace sqlproxy {

struct JwtConfig {
    std::string issuer;
    std::string audience;
    std::string secret;            // HMAC-SHA256 secret (base64 or raw)
    std::string roles_claim = "roles";
};

/**
 * @brief JWT authentication provider
 *
 * Validates Bearer JWT tokens using HMAC-SHA256.
 * Extracts user from 'sub' claim and roles from configurable claim.
 */
class JwtAuthProvider : public IAuthProvider {
public:
    explicit JwtAuthProvider(JwtConfig config);

    [[nodiscard]] AuthResult authenticate(
        const std::string& auth_header,
        const std::string& body_user) override;

    [[nodiscard]] std::string name() const override { return "jwt"; }

private:
    [[nodiscard]] bool verify_hmac_sha256(
        const std::string& signing_input,
        const std::string& signature) const;

    static std::string base64url_decode(const std::string& input);

    JwtConfig config_;
};

} // namespace sqlproxy
