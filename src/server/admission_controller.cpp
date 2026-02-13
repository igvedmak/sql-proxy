#include "server/admission_controller.hpp"

namespace sqlproxy {

AdmissionController::AdmissionController() = default;

AdmissionController::AdmissionController(const Config& config)
    : config_(config) {}

bool AdmissionController::try_admit(PriorityLevel priority) {
    const uint32_t current = active_.load(std::memory_order_relaxed);
    const float utilization = static_cast<float>(current) /
                              static_cast<float>(config_.max_concurrent);

    // Determine minimum priority level for current load
    PriorityLevel min_allowed = PriorityLevel::BACKGROUND;
    if (utilization >= config_.tier3_threshold) {
        min_allowed = PriorityLevel::HIGH;
    } else if (utilization >= config_.tier2_threshold) {
        min_allowed = PriorityLevel::NORMAL;
    } else if (utilization >= config_.tier1_threshold) {
        min_allowed = PriorityLevel::LOW;
    }

    if (priority < min_allowed) {
        rejected_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // Admit: increment active count
    active_.fetch_add(1, std::memory_order_relaxed);
    admitted_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

void AdmissionController::release() {
    active_.fetch_sub(1, std::memory_order_relaxed);
}

AdmissionController::Stats AdmissionController::get_stats() const {
    return {
        .admitted = admitted_.load(std::memory_order_relaxed),
        .rejected = rejected_.load(std::memory_order_relaxed),
        .active = active_.load(std::memory_order_relaxed),
        .max_concurrent = config_.max_concurrent,
    };
}

} // namespace sqlproxy
