// Route Provenance - synthetic scale suite.
//
// Every figure produced here is synthetic: it exercises provenance volume and graph shape, and
// it is not evidence about any physical network.
#include <iostream>
#include <string>
#include <vector>

#include "harness.hpp"
#include "support.hpp"

using namespace rp_test;
using namespace route_provenance;

RP_TEST(scale, one_thousand_lineages_round_trip) {
  Fixture fixture;
  constexpr std::uint64_t kLineages = 1000;
  for (std::uint64_t index = 0; index < kLineages; ++index) {
    RP_REQUIRE_HAS_VALUE(fixture.publish_root(10000 + index, "scale/route-" + std::to_string(index)));
  }
  const auto stats = fixture.store.stats();
  RP_REQUIRE_HAS_VALUE(stats);
  RP_EXPECT_EQ(stats.value().lineage_count, kLineages);
  RP_EXPECT_EQ(stats.value().node_count, kLineages);

  const std::string directory = make_temp_dir("scale-1k", scratch_dir());
  const std::string path = directory + "/scale.rpstore";
  RP_EXPECT_EQ(fixture.store.save(path).outcome(), Outcome::Ok);
  ProvenanceStore restored;
  RP_EXPECT_TRUE(!outcome_is_rejection(restored.load(path).outcome()));
  const auto restored_stats = restored.stats();
  RP_REQUIRE_HAS_VALUE(restored_stats);
  RP_EXPECT_EQ(restored_stats.value().lineage_count, kLineages);
  remove_dir(directory);
  std::cout << "synthetic_scale lineages=" << kLineages << "\n";
}

RP_TEST(scale, ten_thousand_lineages_remain_exact) {
  Limits limits = Limits::defaults();
  limits.max_query_results = 16384;
  limits.max_visited_nodes = 32768;
  limits.max_explanation_nodes = 16384;
  Fixture fixture(limits);
  constexpr std::uint64_t kLineages = 10000;
  for (std::uint64_t index = 0; index < kLineages; ++index) {
    const auto published =
        fixture.publish_root(50000 + index, "scale/wide-" + std::to_string(index));
    if (!published.has_value()) {
      RP_FAIL("publication failed at lineage " + std::to_string(index) + ": " +
              std::string(to_string(published.outcome())));
      break;
    }
  }
  const auto stats = fixture.store.stats();
  RP_REQUIRE_HAS_VALUE(stats);
  RP_EXPECT_EQ(stats.value().lineage_count, kLineages);
  // Exact reverse-index lookups stay possible at this size, and an over-narrow bound is
  // reported rather than silently truncated.
  const auto over_bounded =
      fixture.store.publications_by_publisher_boot(fixture.boot, TraversalBounds{1, 4, 16});
  RP_EXPECT_EQ(over_bounded.outcome(), Outcome::ResourceLimit);
  const auto by_boot = fixture.store.publications_by_publisher_boot(fixture.boot, TraversalBounds{});
  RP_REQUIRE_HAS_VALUE(by_boot);
  RP_EXPECT_EQ(by_boot.value().size(), kLineages);
  std::cout << "synthetic_scale lineages=" << kLineages << "\n";
}

RP_TEST(scale, deep_chain_and_broad_dag_shapes_hold) {
  // Deep chain: one lineage with 400 generations.
  {
    Fixture fixture;
    Limits limits = Limits::defaults();
    limits.max_history_nodes_per_lineage = 1000;
    limits.max_traversal_depth = 1024;
    limits.max_query_results = 4096;
    limits.max_nodes_per_lineage = 4096;
    Fixture deep(limits);
    RP_REQUIRE_HAS_VALUE(deep.publish_root(60001, "scale/deep"));
    for (std::uint64_t generation = 2; generation <= 400; ++generation) {
      const auto published =
          deep.publish_successor(60001, "scale/deep", generation, ReasonCode::RouteReplaced);
      if (!published.has_value()) {
        RP_FAIL("deep chain failed at generation " + std::to_string(generation) + ": " +
                std::string(to_string(published.outcome())));
        break;
      }
    }
    const auto lineage = deep.store.lineage_for_route(RouteId::from_value(60001));
    RP_REQUIRE_HAS_VALUE(lineage);
    RP_EXPECT_EQ(lineage.value().node_count, 400ULL);
    TraversalBounds bounds;
    bounds.max_results = 4096;
    const auto chain = deep.store.predecessor_chain(lineage.value().current_node, bounds);
    RP_REQUIRE_HAS_VALUE(chain);
    RP_EXPECT_EQ(chain.value().nodes.size(), 400U);
    std::cout << "synthetic_scale deep_chain_nodes=" << lineage.value().node_count << "\n";
  }
  // Broad DAG: one root with many successor branches.
  {
    Fixture fixture;
    RP_REQUIRE_HAS_VALUE(fixture.publish_root(60002, "scale/broad"));
    const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(60002));
    RP_REQUIRE_HAS_VALUE(lineage);
    const ProvenanceNodeId root = lineage.value().current_node;
    for (std::uint64_t branch = 0; branch < 60; ++branch) {
      route_provenance::PublishRouteRequest request =
          fixture.route_request(60002, "scale/broad", 2 + branch, ReasonCode::RouteReplaced);
      EdgeSpec edge;
      edge.type = EdgeType::DerivedFrom;
      edge.target = root;
      request.edges.push_back(edge);
      const auto published = fixture.store.publish_route(request);
      if (!published.has_value()) {
        RP_FAIL("broad DAG failed at branch " + std::to_string(branch) + ": " +
                std::string(to_string(published.outcome())));
        break;
      }
    }
    const auto descendants = fixture.store.descendants(root, TraversalBounds{1, 128, 256});
    RP_REQUIRE_HAS_VALUE(descendants);
    RP_EXPECT_EQ(descendants.value().nodes.size(), 61U);
    std::cout << "synthetic_scale broad_dag_nodes=" << descendants.value().nodes.size() << "\n";
  }
}
