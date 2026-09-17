// Route Provenance - oracle suite: differential testing against an independent implementation.
#include <algorithm>
#include <set>
#include <string>
#include <vector>

#include "harness.hpp"
#include "oracle.hpp"
#include "route_provenance/graph.hpp"
#include "support.hpp"

using namespace rp_test;
using namespace route_provenance;

RP_TEST(oracle, the_oracle_itself_is_verified) {
  RP_EXPECT_TRUE(rp_test::oracle_is_verified());
}

RP_TEST(oracle, independent_implementation_agrees_on_acceptance_and_order) {
  SeededRandom random(0x51A7C0DEULL);
  for (int round = 0; round < 40; ++round) {
    Fixture fixture;
    ProvenanceGraph graph;
    GraphOracle oracle;
    Limits limits = Limits::defaults();
    std::vector<ProvenanceNodeId> ids;

    const std::uint64_t node_count = 3 + random.below(6);
    for (std::uint64_t index = 0; index < node_count; ++index) {
      ProvenanceNode node;
      node.lineage = RouteLineageId::from_value(1);
      node.kind = NodeKind::RouteGeneration;
      node.route = RouteId::from_value(1);
      node.route_generation = RouteGeneration::from_value(index + 1);
      node.route_state_digest = Digest::hash("oracle" + std::to_string(round) + ":" +
                                             std::to_string(index));
      node.lifecycle = NodeLifecycle::Current;
      node.authority.scope = AuthorityScope::fabric();
      node.authority.attempt = MutationAttemptId::from_value(index + 1);
      node.authority.publisher = PublisherIdentity{PublisherId::from_value(1), WorkerBootId::from_value(1),
                                                  CoordinatorEpoch::from_value(1)};
      finalize_node(node);
      RP_REQUIRE_TRUE(graph.add_node(node, limits).is_ok());
      ids.push_back(node.id);
      oracle.add_node(node.id.value());
    }
    for (std::uint64_t attempt = 0; attempt < node_count * 2; ++attempt) {
      const std::uint64_t from_index = random.below(node_count);
      const std::uint64_t to_index = random.below(node_count);
      if (from_index == to_index) {
        continue;
      }
      ProvenanceEdge edge;
      edge.lineage = RouteLineageId::from_value(1);
      edge.type = EdgeType::DerivedFrom;
      edge.from = ids[static_cast<std::size_t>(from_index)];
      edge.to = ids[static_cast<std::size_t>(to_index)];
      const std::uint64_t low = std::min(from_index, to_index) + 1;
      const std::uint64_t high = std::max(from_index, to_index) + 1;
      edge.predecessor_route_generation = RouteGeneration::from_value(low);
      edge.successor_route_generation = RouteGeneration::from_value(high);
      edge.authority.scope = AuthorityScope::fabric();
      edge.authority.attempt = MutationAttemptId::from_value(1000 + attempt);
      edge.authority.publisher = PublisherIdentity{PublisherId::from_value(1), WorkerBootId::from_value(1),
                                                  CoordinatorEpoch::from_value(1)};
      finalize_edge(edge);
      const Status graph_status = graph.add_edge(edge, limits);
      const bool oracle_accepted = oracle.add_edge(edge.from.value(), edge.to.value());
      const bool graph_accepted = graph_status.is_ok();
      RP_EXPECT_EQ(graph_accepted, oracle_accepted);
    }
    RP_EXPECT_EQ(graph.validate_structure().is_ok(), !oracle.has_cycle());

    // Ancestry and descendants agree as sets for every node.
    for (const ProvenanceNodeId id : ids) {
      TraversalResult forward;
      RP_REQUIRE_TRUE(graph.traverse(id, TraversalDirection::Outgoing, TraversalBounds{}, limits,
                                     forward)
                          .is_ok());
      std::set<std::uint64_t> graph_set;
      for (const TraversalEntry& entry : forward.nodes) {
        if (entry.node.id != id) {
          graph_set.insert(entry.node.id.value());
        }
      }
      const std::vector<std::uint64_t> oracle_values = oracle.ancestors(id.value());
      std::set<std::uint64_t> oracle_set(oracle_values.begin(), oracle_values.end());
      if (graph_set != oracle_set) {
        RP_FAIL("ancestor sets disagree: graph=" + std::to_string(graph_set.size()) + " oracle=" +
                std::to_string(oracle_set.size()));
      }

      TraversalResult backward;
      RP_REQUIRE_TRUE(graph.traverse(id, TraversalDirection::Incoming, TraversalBounds{}, limits,
                                     backward)
                          .is_ok());
      std::set<std::uint64_t> reverse_graph;
      for (const TraversalEntry& entry : backward.nodes) {
        if (entry.node.id != id) {
          reverse_graph.insert(entry.node.id.value());
        }
      }
      const std::vector<std::uint64_t> oracle_descendants = oracle.descendants(id.value());
      std::set<std::uint64_t> oracle_descendant_set(oracle_descendants.begin(),
                                                    oracle_descendants.end());
      if (reverse_graph != oracle_descendant_set) {
        RP_FAIL("descendant sets disagree: graph=" + std::to_string(reverse_graph.size()) +
                " oracle=" + std::to_string(oracle_descendant_set.size()));
      }
    }

    // The produced topological order is a valid linearisation that agrees with the oracle's.
    const auto order = graph.topological_order();
    RP_REQUIRE_TRUE(order.has_value());
    RP_EXPECT_EQ(order->size(), ids.size());
    const std::vector<std::uint64_t> oracle_order = oracle.topological();
    RP_EXPECT_EQ(oracle_order.size(), ids.size());
    std::vector<std::uint64_t> graph_order;
    for (const ProvenanceNodeId id : *order) {
      graph_order.push_back(id.value());
    }
    RP_EXPECT_TRUE(graph_order == oracle_order);
  }
}
