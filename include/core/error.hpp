#pragma once

#include <string>
#include <system_error>
#include <optional>

namespace sqlproxy {

/**
 * @brief Error categories for the proxy
 */
enum class ErrorCategory {
    NONE,
    PARSE_ERROR,
    POLICY_ERROR,
    EXECUTION_ERROR,
    RATE_LIMIT_ERROR,
    CIRCUIT_BREAKER_ERROR,
    INTERNAL_ERROR
};

/**
 * @brief Result type for operations that can fail
 */
template<typename T>
class Result {
public:
    static Result ok(T value) {
        Result r;
        r.success_ = true;
        r.value_ = std::move(value);
        return r;
    }

    static Result error(ErrorCategory category, std::string message) {
        Result r;
        r.success_ = false;
        r.error_category_ = category;
        r.error_message_ = std::move(message);
        return r;
    }

    bool is_ok() const { return success_; }
    bool is_error() const { return !success_; }

    const T& value() const { return *value_; }
    T& value() { return *value_; }

    ErrorCategory error_category() const { return error_category_; }
    const std::string& error_message() const { return error_message_; }

private:
    bool success_ = false;
    std::optional<T> value_;
    ErrorCategory error_category_ = ErrorCategory::NONE;
    std::string error_message_;
};

} // namespace sqlproxy
