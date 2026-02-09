#pragma once

#include <string_view>

namespace sqlproxy::ast {

// libpg_query JSON node types (shared across parsers and analyzer)
inline constexpr std::string_view kRangeVar   = "RangeVar";
inline constexpr std::string_view kRelname    = "relname";
inline constexpr std::string_view kSchemaname = "schemaname";
inline constexpr std::string_view kAlias      = "Alias";
inline constexpr std::string_view kAliasFld   = "alias";
inline constexpr std::string_view kAliasname  = "aliasname";
inline constexpr std::string_view kSval       = "sval";
inline constexpr std::string_view kStr        = "str";

// Common error messages
inline constexpr std::string_view kUnknownParseError = "Unknown parse error";

} // namespace sqlproxy::ast
