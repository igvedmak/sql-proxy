#pragma once

#include "server/http_server.hpp"  // UserInfo
#include <memory>
#include <string>
#include <unordered_map>

namespace sqlproxy {

// Forward declarations
class PolicyEngine;
class IRateLimiter;
class AuditEmitter;

struct TenantContext {
    std::string tenant_id;
    std::shared_ptr<PolicyEngine> policy_engine;
    std::shared_ptr<IRateLimiter> rate_limiter;
    std::shared_ptr<AuditEmitter> audit_emitter;
    std::unordered_map<std::string, UserInfo> users;
};

} // namespace sqlproxy
