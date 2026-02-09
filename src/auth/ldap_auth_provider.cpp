#include "auth/ldap_auth_provider.hpp"
#include "core/utils.hpp"

#include <format>

#ifdef ENABLE_LDAP
#include <ldap.h>
#endif

namespace sqlproxy {

LdapAuthProvider::LdapAuthProvider(LdapConfig config)
    : config_(std::move(config)) {}

std::pair<std::string, std::string> LdapAuthProvider::decode_basic_auth(
    const std::string& auth_header) {

    constexpr std::string_view kBasicPrefix = "Basic ";
    if (auth_header.size() <= kBasicPrefix.size() ||
        std::string_view(auth_header).substr(0, kBasicPrefix.size()) != kBasicPrefix) {
        return {"", ""};
    }

    // Decode base64 credentials
    std::string encoded(std::string_view(auth_header).substr(kBasicPrefix.size()));

    // Simple base64 decode
    static const std::string b64chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string decoded;
    decoded.reserve(encoded.size() * 3 / 4);

    uint32_t bits = 0;
    int bit_count = 0;
    for (char c : encoded) {
        if (c == '=') break;
        auto idx = b64chars.find(c);
        if (idx == std::string::npos) continue;
        bits = (bits << 6) | static_cast<uint32_t>(idx);
        bit_count += 6;
        if (bit_count >= 8) {
            bit_count -= 8;
            decoded += static_cast<char>((bits >> bit_count) & 0xFF);
        }
    }

    // Split on ':'
    auto colon = decoded.find(':');
    if (colon == std::string::npos) return {"", ""};

    return {decoded.substr(0, colon), decoded.substr(colon + 1)};
}

IAuthProvider::AuthResult LdapAuthProvider::authenticate(
    const std::string& auth_header,
    const std::string& /*body_user*/) {

    AuthResult result;

#ifdef ENABLE_LDAP
    auto [username, password] = decode_basic_auth(auth_header);
    if (username.empty() || password.empty()) {
        result.error = "LDAP: missing Basic auth credentials";
        return result;
    }

    // Initialize LDAP connection
    LDAP* ld = nullptr;
    int rc = ldap_initialize(&ld, config_.url.c_str());
    if (rc != LDAP_SUCCESS) {
        result.error = std::format("LDAP: failed to initialize: {}", ldap_err2string(rc));
        return result;
    }

    // Set LDAP v3
    int version = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    // Build user filter
    std::string filter = config_.user_filter;
    auto brace = filter.find("{}");
    if (brace != std::string::npos) {
        filter.replace(brace, 2, username);
    }

    // Bind with admin credentials for search
    struct berval cred;
    cred.bv_val = const_cast<char*>(config_.bind_password.c_str());
    cred.bv_len = config_.bind_password.size();

    rc = ldap_sasl_bind_s(ld, config_.bind_dn.c_str(), LDAP_SASL_SIMPLE, &cred,
                          nullptr, nullptr, nullptr);
    if (rc != LDAP_SUCCESS) {
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        result.error = std::format("LDAP: admin bind failed: {}", ldap_err2string(rc));
        return result;
    }

    // Search for user
    LDAPMessage* search_result = nullptr;
    rc = ldap_search_ext_s(ld, config_.base_dn.c_str(), LDAP_SCOPE_SUBTREE,
                           filter.c_str(), nullptr, 0,
                           nullptr, nullptr, nullptr, 1, &search_result);
    if (rc != LDAP_SUCCESS || ldap_count_entries(ld, search_result) == 0) {
        if (search_result) ldap_msgfree(search_result);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        result.error = std::format("LDAP: user '{}' not found", username);
        return result;
    }

    // Get user DN
    LDAPMessage* entry = ldap_first_entry(ld, search_result);
    char* dn = ldap_get_dn(ld, entry);
    std::string user_dn(dn);
    ldap_memfree(dn);

    // Extract group memberships
    struct berval** values = ldap_get_values_len(ld, entry,
        config_.group_attribute.c_str());
    if (values) {
        for (int i = 0; values[i] != nullptr; ++i) {
            result.roles.emplace_back(values[i]->bv_val, values[i]->bv_len);
        }
        ldap_value_free_len(values);
    }

    ldap_msgfree(search_result);

    // Bind as user to verify password
    cred.bv_val = const_cast<char*>(password.c_str());
    cred.bv_len = password.size();

    rc = ldap_sasl_bind_s(ld, user_dn.c_str(), LDAP_SASL_SIMPLE, &cred,
                          nullptr, nullptr, nullptr);
    ldap_unbind_ext_s(ld, nullptr, nullptr);

    if (rc != LDAP_SUCCESS) {
        result.error = std::format("LDAP: authentication failed for '{}'", username);
        return result;
    }

    result.authenticated = true;
    result.user = username;
    if (result.roles.empty()) {
        result.roles.push_back("user");
    }
#else
    result.error = "LDAP support not compiled (ENABLE_LDAP=OFF)";
#endif

    return result;
}

} // namespace sqlproxy
