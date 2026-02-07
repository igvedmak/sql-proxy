#pragma once

#include "db/idb_backend.hpp"
#include "core/database_type.hpp"
#include <memory>
#include <unordered_map>
#include <functional>
#include <stdexcept>

namespace sqlproxy {

/**
 * @brief Registry for database backends
 *
 * Backends register themselves at startup via static initialization.
 * The registry is queried by DatabaseType to instantiate the right backend.
 *
 * Usage:
 *   // Registration (in pg_backend.cpp):
 *   BackendRegistry::instance().register_backend(
 *       DatabaseType::POSTGRESQL, []{ return std::make_unique<PgBackend>(); });
 *
 *   // Creation (in main.cpp):
 *   auto backend = BackendRegistry::instance().create(DatabaseType::POSTGRESQL);
 */
class BackendRegistry {
public:
    using Factory = std::function<std::unique_ptr<IDbBackend>()>;

    static BackendRegistry& instance() {
        static BackendRegistry registry;
        return registry;
    }

    void register_backend(DatabaseType type, Factory factory) {
        factories_[type] = std::move(factory);
    }

    [[nodiscard]] std::unique_ptr<IDbBackend> create(DatabaseType type) const {
        const auto it = factories_.find(type);
        if (it == factories_.end()) {
            throw std::runtime_error(
                std::string("No backend registered for database type: ") +
                database_type_to_string(type));
        }
        return it->second();
    }

    [[nodiscard]] bool has_backend(DatabaseType type) const {
        return factories_.count(type) > 0;
    }

private:
    BackendRegistry() = default;

    // Use a simple struct hash for DatabaseType
    struct DatabaseTypeHash {
        size_t operator()(DatabaseType t) const {
            return std::hash<int>()(static_cast<int>(t));
        }
    };

    std::unordered_map<DatabaseType, Factory, DatabaseTypeHash> factories_;
};

} // namespace sqlproxy
