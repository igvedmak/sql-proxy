#pragma once

#include "db/iquery_executor.hpp"
#include <atomic>
#include <string>

namespace sqlproxy::testing {

/**
 * @brief Mock query executor for testing routing/splitting logic
 */
class MockQueryExecutor : public IQueryExecutor {
public:
    explicit MockQueryExecutor(bool should_succeed = true,
                                std::string label = "mock")
        : should_succeed_(should_succeed), label_(std::move(label)) {}

    [[nodiscard]] QueryResult execute(
        const std::string& /*sql*/, StatementType /*stmt_type*/) override {
        execute_count_.fetch_add(1, std::memory_order_relaxed);
        QueryResult result;
        result.success = should_succeed_;
        if (should_succeed_) {
            result.column_names = {"result"};
            result.rows = {{label_}};
        } else {
            result.error_code = ErrorCode::DATABASE_ERROR;
            result.error_message = "Mock failure: " + label_;
        }
        return result;
    }

    [[nodiscard]] uint64_t execute_count() const {
        return execute_count_.load(std::memory_order_relaxed);
    }

    void set_should_succeed(bool v) { should_succeed_ = v; }

private:
    bool should_succeed_;
    std::string label_;
    std::atomic<uint64_t> execute_count_{0};
};

} // namespace sqlproxy::testing
