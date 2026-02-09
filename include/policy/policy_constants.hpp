#pragma once

#include <string>
#include <string_view>

namespace sqlproxy::policy {

// kWildcard is std::string (not string_view) because it's used as a map key
inline const std::string kWildcard = "*";
inline constexpr std::string_view kDefaultDeny = "default_deny";
inline constexpr std::string_view kDefaultSchema = "public";

} // namespace sqlproxy::policy
