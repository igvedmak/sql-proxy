#include <catch2/catch_test_macros.hpp>
#include "parser/parse_cache.hpp"

using namespace sqlproxy;

static std::shared_ptr<StatementInfo> make_entry(uint64_t hash,
                                                  const std::string& normalized,
                                                  std::vector<std::string> table_names) {
    QueryFingerprint fp(hash, normalized);
    ParsedQuery pq;
    pq.type = StatementType::SELECT;
    for (auto& t : table_names) {
        TableRef ref;
        ref.table = std::move(t);
        pq.tables.push_back(std::move(ref));
    }
    return std::make_shared<StatementInfo>(std::move(fp), std::move(pq));
}

TEST_CASE("ParseCache: invalidate_table removes only matching entries", "[parse_cache][ddl]") {
    ParseCache cache(100, 4);

    cache.put(make_entry(1, "SELECT * FROM customers", {"customers"}));
    cache.put(make_entry(2, "SELECT * FROM orders", {"orders"}));
    cache.put(make_entry(3, "SELECT * FROM order_items", {"order_items"}));

    auto stats_before = cache.get_stats();
    CHECK(stats_before.total_entries == 3);

    size_t removed = cache.invalidate_table("customers");
    CHECK(removed == 1);

    auto stats_after = cache.get_stats();
    CHECK(stats_after.total_entries == 2);
    CHECK(stats_after.ddl_invalidations == 1);

    // customers entry should be gone
    CHECK_FALSE(cache.get(QueryFingerprint(1, "SELECT * FROM customers")).has_value());
    // orders and order_items should still be there
    CHECK(cache.get(QueryFingerprint(2, "SELECT * FROM orders")).has_value());
    CHECK(cache.get(QueryFingerprint(3, "SELECT * FROM order_items")).has_value());
}

TEST_CASE("ParseCache: multi-table entry invalidated when any table DDL'd", "[parse_cache][ddl]") {
    ParseCache cache(100, 4);

    // Entry references both customers and orders
    cache.put(make_entry(10, "SELECT c.*, o.* FROM customers c JOIN orders o",
                         {"customers", "orders"}));
    // Entry references only orders
    cache.put(make_entry(11, "SELECT * FROM orders", {"orders"}));

    CHECK(cache.get_stats().total_entries == 2);

    // DDL on customers invalidates the join entry
    size_t removed = cache.invalidate_table("customers");
    CHECK(removed == 1);
    CHECK(cache.get_stats().total_entries == 1);

    // The orders-only entry is still there
    CHECK(cache.get(QueryFingerprint(11, "SELECT * FROM orders")).has_value());
}

TEST_CASE("ParseCache: case-insensitive table name matching", "[parse_cache][ddl]") {
    ParseCache cache(100, 4);

    cache.put(make_entry(20, "SELECT * FROM Customers", {"Customers"}));

    // Lowercase invalidation should match
    size_t removed = cache.invalidate_table("customers");
    CHECK(removed == 1);
    CHECK(cache.get_stats().ddl_invalidations == 1);
}

TEST_CASE("ParseCache: empty cache invalidation returns 0", "[parse_cache][ddl]") {
    ParseCache cache(100, 4);

    size_t removed = cache.invalidate_table("nonexistent");
    CHECK(removed == 0);
    CHECK(cache.get_stats().ddl_invalidations == 0);
}

TEST_CASE("ParseCache: ddl_invalidations counter accumulates", "[parse_cache][ddl]") {
    ParseCache cache(100, 4);

    cache.put(make_entry(30, "SELECT * FROM customers", {"customers"}));
    cache.put(make_entry(31, "SELECT * FROM orders", {"orders"}));

    cache.invalidate_table("customers");
    cache.invalidate_table("orders");

    auto stats = cache.get_stats();
    CHECK(stats.ddl_invalidations == 2);
    CHECK(stats.total_entries == 0);
}
