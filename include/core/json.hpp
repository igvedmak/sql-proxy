#pragma once

#include <glaze/glaze.hpp>

#include <cmath>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace sqlproxy {

/**
 * @brief Thin wrapper around glz::json_t providing nlohmann-compatible API
 *
 * Stores json_t by value. Const operator[] returns copies (safe for recursive
 * AST walks). Used for JSON DOM navigation in the SQL parser/analyzer.
 *
 * For mutation (TOML parser), use glz::json_t directly and convert to
 * JsonValue at the boundary via the implicit constructor.
 */
class JsonValue {
public:
    using array_t = glz::json_t::array_t;
    using object_t = glz::json_t::object_t;
    using null_t = glz::json_t::null_t;

    struct parse_error : std::runtime_error {
        using std::runtime_error::runtime_error;
    };

    // ===== Constructors =====

    JsonValue() = default;
    JsonValue(glz::json_t v) : data_(std::move(v)) {}
    JsonValue(std::nullptr_t) {}
    JsonValue(bool v) { data_ = v; }
    JsonValue(int v) { data_ = static_cast<double>(v); }
    JsonValue(long long v) { data_ = static_cast<double>(v); }
    JsonValue(double v) { data_ = v; }
    JsonValue(const char* v) { data_ = std::string(v); }
    JsonValue(const std::string& v) { data_ = v; }
    JsonValue(std::string&& v) { data_ = std::move(v); }

    // ===== Type Checks =====

    [[nodiscard]] bool is_null() const { return data_.is_null(); }
    [[nodiscard]] bool is_object() const { return data_.is_object(); }
    [[nodiscard]] bool is_array() const { return data_.is_array(); }
    [[nodiscard]] bool is_string() const { return data_.is_string(); }
    [[nodiscard]] bool is_number() const { return data_.is_number(); }
    [[nodiscard]] bool is_boolean() const { return data_.is_boolean(); }

    [[nodiscard]] bool is_number_integer() const {
        if (!data_.is_number()) return false;
        double d = data_.get<double>();
        return d == std::floor(d) && std::isfinite(d);
    }

    [[nodiscard]] bool is_number_float() const {
        return data_.is_number() && !is_number_integer();
    }

    // ===== Container Properties =====

    [[nodiscard]] bool empty() const { return data_.empty(); }
    [[nodiscard]] size_t size() const { return data_.size(); }
    [[nodiscard]] bool contains(std::string_view key) const {
        if (!data_.is_object()) return false;
        const auto& obj = data_.get_object();
        return obj.find(std::string(key)) != obj.end();
    }

    // ===== Const Element Access (returns copy) =====

    [[nodiscard]] JsonValue operator[](std::string_view key) const {
        if (!data_.is_object()) return {};
        const auto& obj = data_.get_object();
        auto it = obj.find(std::string(key));
        if (it != obj.end()) return JsonValue(it->second);
        return {};
    }

    [[nodiscard]] JsonValue operator[](size_t idx) const {
        if (!data_.is_array()) return {};
        const auto& arr = data_.get_array();
        if (idx < arr.size()) return JsonValue(arr[idx]);
        return {};
    }

    [[nodiscard]] JsonValue back() const {
        if (!data_.is_array()) return {};
        const auto& arr = data_.get_array();
        if (arr.empty()) return {};
        return JsonValue(arr.back());
    }

    // ===== Value Extraction =====

    template <typename T>
    [[nodiscard]] T get() const {
        if constexpr (std::is_same_v<T, std::string>) {
            return data_.get<std::string>();
        } else if constexpr (std::is_same_v<T, bool>) {
            return data_.get<bool>();
        } else if constexpr (std::is_same_v<T, double>) {
            return data_.get<double>();
        } else if constexpr (std::is_integral_v<T>) {
            // json_t stores all numbers as double; cast to target integral type
            return static_cast<T>(data_.get<double>());
        } else {
            static_assert(!sizeof(T), "Unsupported type for JsonValue::get<T>()");
        }
    }

    // value() with default (nlohmann-compatible: node.value("key", default))
    template <typename T>
    [[nodiscard]] T value(std::string_view key, T default_value) const {
        if (!data_.is_object()) return default_value;
        const auto& obj = data_.get_object();
        auto it = obj.find(std::string(key));
        if (it == obj.end()) return default_value;
        return JsonValue(it->second).get<T>();
    }

    // ===== Unified Iterator (arrays + objects) =====

    class const_iterator {
        friend class JsonValue;
        enum class Kind { ARRAY, OBJECT, END };

        Kind kind_ = Kind::END;
        const array_t* arr_ = nullptr;
        size_t arr_idx_ = 0;
        object_t::const_iterator obj_it_{};

        const_iterator(const array_t* arr, size_t idx)
            : kind_(Kind::ARRAY), arr_(arr), arr_idx_(idx) {}
        const_iterator(object_t::const_iterator it, Kind /*tag*/)
            : kind_(Kind::OBJECT), obj_it_(it) {}
        const_iterator() = default;

    public:
        // Dereference: for arrays, returns value; for objects, returns value
        [[nodiscard]] JsonValue operator*() const {
            if (kind_ == Kind::ARRAY) return JsonValue((*arr_)[arr_idx_]);
            if (kind_ == Kind::OBJECT) return JsonValue(obj_it_->second);
            return {};
        }

        // Object-specific accessors (nlohmann-compatible)
        [[nodiscard]] const std::string& key() const { return obj_it_->first; }
        [[nodiscard]] JsonValue value() const {
            if (kind_ == Kind::OBJECT) return JsonValue(obj_it_->second);
            if (kind_ == Kind::ARRAY) return JsonValue((*arr_)[arr_idx_]);
            return {};
        }

        const_iterator& operator++() {
            if (kind_ == Kind::ARRAY) ++arr_idx_;
            else if (kind_ == Kind::OBJECT) ++obj_it_;
            return *this;
        }

        [[nodiscard]] bool operator==(const const_iterator& o) const {
            if (kind_ != o.kind_) return false;
            if (kind_ == Kind::ARRAY) return arr_idx_ == o.arr_idx_;
            if (kind_ == Kind::OBJECT) return obj_it_ == o.obj_it_;
            return true; // both END
        }

        [[nodiscard]] bool operator!=(const const_iterator& o) const { return !(*this == o); }
    };

    [[nodiscard]] const_iterator begin() const {
        if (data_.is_array()) {
            const auto& arr = data_.get_array();
            return const_iterator(&arr, 0);
        }
        if (data_.is_object()) {
            const auto& obj = data_.get_object();
            return const_iterator(obj.begin(), const_iterator::Kind::OBJECT);
        }
        return {};
    }

    [[nodiscard]] const_iterator end() const {
        if (data_.is_array()) {
            const auto& arr = data_.get_array();
            return const_iterator(&arr, arr.size());
        }
        if (data_.is_object()) {
            const auto& obj = data_.get_object();
            return const_iterator(obj.end(), const_iterator::Kind::OBJECT);
        }
        return {};
    }

    // ===== Items Range (for structured bindings over objects) =====

    class items_range {
        const object_t* obj_;

    public:
        explicit items_range(const object_t* obj) : obj_(obj) {}

        class iterator {
            object_t::const_iterator it_;

        public:
            explicit iterator(object_t::const_iterator it) : it_(it) {}

            [[nodiscard]] std::pair<std::string, JsonValue> operator*() const {
                return {it_->first, JsonValue(it_->second)};
            }

            iterator& operator++() { ++it_; return *this; }
            [[nodiscard]] bool operator!=(const iterator& o) const { return it_ != o.it_; }
        };

        [[nodiscard]] iterator begin() const { return iterator(obj_->begin()); }
        [[nodiscard]] iterator end() const { return iterator(obj_->end()); }
    };

    [[nodiscard]] items_range items() const {
        static const object_t empty_obj;
        if (data_.is_object()) {
            return items_range(&data_.get_object());
        }
        return items_range(&empty_obj);
    }

    // ===== Static Factories =====

    [[nodiscard]] static JsonValue object() {
        glz::json_t j;
        j = object_t{};
        return JsonValue(std::move(j));
    }

    [[nodiscard]] static JsonValue array() {
        glz::json_t j;
        j = array_t{};
        return JsonValue(std::move(j));
    }

    [[nodiscard]] static JsonValue parse(const std::string& json_str) {
        glz::json_t result;
        auto ec = glz::read_json(result, json_str);
        if (ec) {
            throw parse_error("JSON parse error");
        }
        return JsonValue(std::move(result));
    }

    [[nodiscard]] static JsonValue parse(const char* json_str) {
        return parse(std::string(json_str));
    }

    // Helper: create {"key": value} object (replaces mutable operator[] pattern)
    [[nodiscard]] static JsonValue wrap(std::string_view key, JsonValue val) {
        glz::json_t j;
        object_t obj;
        obj[std::string(key)] = std::move(val.data_);
        j = std::move(obj);
        return JsonValue(std::move(j));
    }

    // ===== Raw Access =====

    [[nodiscard]] glz::json_t& raw() { return data_; }
    [[nodiscard]] const glz::json_t& raw() const { return data_; }

private:
    glz::json_t data_{};
};

} // namespace sqlproxy
