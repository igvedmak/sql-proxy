#pragma once

#include <string>
#include <chrono>
#include <random>
#include <format>
#include <sstream>
#include <cstdio>
#include <iostream>
#include <limits>
#include <mutex>
#include <type_traits>

namespace sqlproxy::utils {

// ============================================================================
// UUID Generation
// ============================================================================

inline std::string generate_uuid() {
    static thread_local std::random_device rd;
    static thread_local std::mt19937_64 gen(rd());
    static thread_local std::uniform_int_distribution<uint64_t> dis;

    uint64_t high = dis(gen);
    uint64_t low = dis(gen);

    return std::format("{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        static_cast<uint32_t>(high >> 32),
        static_cast<uint16_t>((high >> 16) & 0xFFFF),
        static_cast<uint16_t>(high & 0xFFFF),
        static_cast<uint16_t>(low >> 48),
        low & 0xFFFFFFFFFFFF);
}

// ============================================================================
// Time Utilities
// ============================================================================

inline std::string format_timestamp(const std::chrono::system_clock::time_point& tp) {
    auto time = std::chrono::system_clock::to_time_t(tp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        tp.time_since_epoch()) % 1000;

    std::tm tm_buf;
    ::localtime_r(&time, &tm_buf);

    char time_buf[32];
    std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%S", &tm_buf);

    char tz_buf[8];
    std::strftime(tz_buf, sizeof(tz_buf), "%z", &tm_buf);

    return std::format("{}.{:03d}{}", time_buf, static_cast<int>(ms.count()), tz_buf);
}

inline std::chrono::system_clock::time_point now() {
    return std::chrono::system_clock::now();
}

// ============================================================================
// Boolean Formatting
// ============================================================================

inline constexpr const char* booltostr(bool x) { return x ? "true" : "false"; }

// ============================================================================
// Type-Safe Range Check (eliminates impossible comparisons at compile time)
// ============================================================================

template<auto Lo, auto Hi, typename T>
constexpr bool in_range(T value) {
    using Common = std::common_type_t<T, decltype(Lo), decltype(Hi)>;
    bool below = false;
    bool above = false;
    if constexpr (static_cast<Common>(std::numeric_limits<T>::min()) >= static_cast<Common>(Lo)) {
        (void)value; // T can never be below Lo
    } else {
        below = static_cast<Common>(value) < static_cast<Common>(Lo);
    }
    if constexpr (static_cast<Common>(std::numeric_limits<T>::max()) <= static_cast<Common>(Hi)) {
        (void)value; // T can never exceed Hi
    } else {
        above = static_cast<Common>(value) > static_cast<Common>(Hi);
    }
    return !below && !above;
}

// ============================================================================
// String Utilities
// ============================================================================

inline std::string to_lower(const std::string& str) {
    std::string result = str;
    for (char& c : result) {
        c = std::tolower(static_cast<unsigned char>(c));
    }
    return result;
}

inline std::string trim(const std::string& str) {
    const auto start = str.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) {
        return "";
    }
    const auto end = str.find_last_not_of(" \t\n\r");
    return str.substr(start, end - start + 1);
}

inline std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::istringstream iss(str);
    std::string token;
    while (std::getline(iss, token, delimiter)) {
        tokens.emplace_back(std::move(token));
    }
    return tokens;
}

// ============================================================================
// Performance Timer
// ============================================================================

class Timer {
public:
    Timer() : start_(std::chrono::steady_clock::now()) {}

    void reset() {
        start_ = std::chrono::steady_clock::now();
    }

    template<typename Duration = std::chrono::microseconds>
    Duration elapsed() const {
        const auto end = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<Duration>(end - start_);
    }

    std::chrono::microseconds elapsed_us() const {
        return elapsed<std::chrono::microseconds>();
    }

    std::chrono::milliseconds elapsed_ms() const {
        return elapsed<std::chrono::milliseconds>();
    }

private:
    std::chrono::steady_clock::time_point start_;
};

// ============================================================================
// RAII Timer for Scoped Measurements
// ============================================================================

template<typename Duration>
class ScopedTimer {
public:
    explicit ScopedTimer(Duration& out) : out_(out), timer_() {}

    ~ScopedTimer() {
        out_ = timer_.elapsed<Duration>();
    }

private:
    Duration& out_;
    Timer timer_;
};

// ============================================================================
// Logging (thread-safe, stderr, level-tagged)
// ============================================================================

namespace log {

enum class Level { INFO, WARN, ERROR };

namespace detail {
    inline std::mutex& log_mutex() {
        static std::mutex m;
        return m;
    }

    inline void write(Level level, const std::string& msg) {
        const char* tag = "";
        switch (level) {
            case Level::INFO:  tag = "INFO "; break;
            case Level::WARN:  tag = "WARN "; break;
            case Level::ERROR: tag = "ERROR"; break;
        }

        const auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        std::tm tm_buf;
        ::localtime_r(&time, &tm_buf);

        char time_buf[16];
        std::strftime(time_buf, sizeof(time_buf), "%H:%M:%S", &tm_buf);

        const auto formatted = std::format("{}.{:03d} [{}] {}\n",
            time_buf, static_cast<int>(ms.count()), tag, msg);

        std::lock_guard<std::mutex> lock(log_mutex());
        std::cerr << formatted;
    }
} // namespace detail

inline void info(const std::string& msg) {
    detail::write(Level::INFO, msg);
}

inline void warn(const std::string& msg) {
    detail::write(Level::WARN, msg);
}

inline void error(const std::string& msg) {
    detail::write(Level::ERROR, msg);
}

} // namespace log

} // namespace sqlproxy::utils
