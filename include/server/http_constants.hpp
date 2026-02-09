#pragma once

#include <string>
#include <string_view>

namespace sqlproxy::http {

inline constexpr std::string_view kBearerPrefix = "Bearer ";
// std::string because cpp-httplib APIs require const std::string&
inline const std::string kAuthorizationHeader = "Authorization";
inline constexpr const char* kJsonContentType = "application/json";

} // namespace sqlproxy::http
