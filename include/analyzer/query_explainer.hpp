#pragma once

#include <optional>
#include <string>
#include <vector>

namespace sqlproxy {

struct AnalysisResult;  // forward declare

class QueryExplainer {
public:
    struct Explanation {
        std::string summary;
        std::string statement_type;
        std::vector<std::string> tables_read;
        std::vector<std::string> tables_written;
        std::vector<std::string> columns_selected;
        std::vector<std::string> columns_filtered;
        std::vector<std::string> columns_written;
        struct {
            bool has_join = false;
            bool has_subquery = false;
            bool has_aggregation = false;
            bool has_star_select = false;
            std::optional<int64_t> limit;
        } characteristics;
    };

    [[nodiscard]] static Explanation explain(const AnalysisResult& analysis);
};

} // namespace sqlproxy
