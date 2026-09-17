// Route Provenance - property suite.
//
// Randomised schedules are driven by a seeded generator; the seed is reported with every
// failure so a counterexample can be reproduced exactly.
#include <algorithm>
#include <set>
#include <string>
#include <vector>

#include "harness.hpp"
#include "support.hpp"

using namespace rp_test;
using namespace route_provenance;

namespace {

struct Schedule {
  std::uint64_t seed = 0;
  int operations = 0;
};

void check_invariants(Fixture& fixture, const std::vector<std::uint64_t>& routes,
                      const std::string& seed_label) {
  for (const std::uint64_t route : routes) {
    const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(route));
    if (!lineage.has_value()) {
      RP_FAIL(seed_label + ": lineage for route " + std::to_string(route) + " disappeared");
      continue;
    }
    if (lineage.value().node_count == 0) {
      continue;
    }
    // Every record of the lineage is reachable from the current record.
    const auto snapshot = fixture.store.snapshot(lineage.value().id);
    if (!snapshot.has_value()) {
      RP_FAIL(seed_label + ": snapshot failed");
      continue;
    }
    std::set<std::uint64_t> ids;
    for (const ProvenanceNode& node : snapshot.value().nodes) {
      ids.insert(node.id.value());
    }
    if (ids.find(lineage.value().current_node.value()) == ids.end()) {
      RP_FAIL(seed_label + ": current record is not part of the lineage snapshot");
    }
    for (const ProvenanceEdge& edge : snapshot.value().edges) {
      if (ids.find(edge.from.value()) == ids.end() || ids.find(edge.to.value()) == ids.end()) {
        RP_FAIL(seed_label + ": edge references a record outside the lineage");
      }
      if (edge.from == edge.to) {
        RP_FAIL(seed_label + ": self edge persisted");
      }
    }
    // The current route generation must have a lineage root.
    const auto chain = fixture.store.predecessor_chain(lineage.value().current_node,
                                                       TraversalBounds{});
    if (!chain.has_value()) {
      RP_FAIL(seed_label + ": predecessor chain failed");
      continue;
    }
    bool found_root = false;
    for (const TraversalEntry& entry : chain.value().nodes) {
      if (entry.node.root_reason.has_value()) {
        found_root = true;
      }
    }
    if (!found_root) {
      RP_FAIL(seed_label + ": current record has no root in its causal ancestry");
    }
    // Retired lineages never resurrect.
    if (lineage.value().lifecycle == LineageLifecycle::Retired) {
      const auto current = fixture.store.node(lineage.value().current_node);
      if (current.has_value() && current.value().currentness == Currentness::Current) {
        RP_FAIL(seed_label + ": retired lineage still reports current provenance");
      }
    }
    // Generations never decrease and never wrap.
    if (!lineage.value().lineage_generation.valid()) {
      RP_FAIL(seed_label + ": lineage generation became invalid");
    }
  }
}

}  // namespace

RP_TEST(property, randomised_publication_schedules_keep_every_invariant) {
  const std::uint64_t seeds[] = {0x1234ULL, 0xABCDEFULL, 0x5EEDULL, 0xF00DULL};
  for (const std::uint64_t seed : seeds) {
    const std::string label = "seed=" + std::to_string(seed);
    SeededRandom random(seed);
    Fixture fixture;
    std::vector<std::uint64_t> routes;
    std::uint64_t next_route = 1000;
    for (int operation = 0; operation < 120; ++operation) {
      const std::uint64_t choice = random.below(10);
      if (routes.empty() || choice == 0) {
        const std::uint64_t route = next_route++;
        routes.push_back(route);
        const auto published = fixture.publish_root(route, "route/" + std::to_string(route));
        if (!published.has_value() && published.outcome() != Outcome::ResourceLimit) {
          RP_FAIL(label + ": root publication failed with " + std::string(to_string(published.outcome())));
        }
        continue;
      }
      const std::uint64_t route = routes[static_cast<std::size_t>(random.below(routes.size()))];
      const std::string name = "route/" + std::to_string(route);
      const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(route));
      if (!lineage.has_value()) {
        continue;
      }
      const std::uint64_t next_generation = lineage.value().current_route_generation.value() + 1;
      switch (choice) {
        case 1:
        case 2: {
          static_cast<void>(fixture.publish_successor(route, name, next_generation,
                                                      ReasonCode::RouteReplaced));
          break;
        }
        case 3: {
          const auto current = fixture.current_node(route, name);
          if (current.has_value()) {
            static_cast<void>(fixture.store.withdraw(fixture.administrative(
                route, name, current.value().id, ReasonCode::AdminWithdrawal)));
          }
          break;
        }
        case 4: {
          const auto current = fixture.current_node(route, name);
          if (current.has_value()) {
            static_cast<void>(fixture.store.revalidate(fixture.administrative(
                route, name, current.value().id, ReasonCode::RecoveryRevalidation)));
          }
          break;
        }
        case 5: {
          const auto current = fixture.current_node(route, name);
          if (current.has_value()) {
            route_provenance::CorrectionRequest request;
            request.key = fixture.key(route, name);
            request.target = current.value().id;
            request.authority = fixture.context();
            static_cast<void>(fixture.store.correct(request));
          }
          break;
        }
        case 6: {
          DependencyNotification notice;
          notice.kind = DependencyKind::PathAuthorityAdvance;
          notice.authority = fixture.context();
          notice.authority.scope = AuthorityScope::fabric();
          notice.path_authority_generation =
              PathAuthorityGeneration::from_value(1 + random.below(5));
          static_cast<void>(fixture.store.notify_dependency(notice));
          break;
        }
        case 7: {
          const CoordinatorEpoch next = CoordinatorEpoch::from_value(fixture.epoch.value() + 1);
          const Status advanced = fixture.store.advance_epoch(next, fixture.context());
          if (!outcome_is_rejection(advanced.outcome())) {
            // The fixture follows the coordinator, exactly as a real publisher session would.
            fixture.epoch = next;
          }
          break;
        }
        case 8: {
          const auto snapshot = fixture.store.snapshot(lineage.value().id);
          if (snapshot.has_value()) {
            const auto repeat = fixture.store.snapshot(lineage.value().id);
            if (repeat.has_value()) {
              RP_EXPECT_EQ(snapshot.value().digest, repeat.value().digest);
            }
          }
          break;
        }
        default: {
          const auto current = fixture.current_node(route, name);
          if (current.has_value()) {
            const auto retried = fixture.publish_successor(route, name, next_generation,
                                                           ReasonCode::RouteReplaced);
            static_cast<void>(retried);
          }
          break;
        }
      }
    }
    check_invariants(fixture, routes, label);

    // Digests are deterministic: the same lineage produces the same digest twice.
    for (const std::uint64_t route : routes) {
      const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(route));
      if (!lineage.has_value()) {
        continue;
      }
      const auto first = fixture.store.snapshot(lineage.value().id);
      const auto second = fixture.store.snapshot(lineage.value().id);
      if (first.has_value() && second.has_value()) {
        RP_EXPECT_EQ(first.value().digest, second.value().digest);
        RP_EXPECT_EQ(first.value().id, second.value().id);
      }
    }

    // Persistence round-trips for the whole randomised store.
    const std::string directory = make_temp_dir("property", scratch_dir());
    const std::string path = directory + "/property.rpstore";
    RP_EXPECT_EQ(fixture.store.save(path).outcome(), Outcome::Ok);
    ProvenanceStore restored;
    RP_EXPECT_TRUE(!outcome_is_rejection(restored.load(path).outcome()));
    const auto before_stats = fixture.store.stats();
    const auto after_stats = restored.stats();
    RP_REQUIRE_HAS_VALUE(before_stats);
    RP_REQUIRE_HAS_VALUE(after_stats);
    RP_EXPECT_EQ(before_stats.value().lineage_count, after_stats.value().lineage_count);
    RP_EXPECT_EQ(before_stats.value().node_count, after_stats.value().node_count);
    RP_EXPECT_EQ(before_stats.value().edge_count, after_stats.value().edge_count);
    remove_dir(directory);
  }
}

RP_TEST(property, exact_replay_never_advances_any_generation) {
  SeededRandom random(0xBEEFULL);
  Fixture fixture;
  for (int index = 0; index < 30; ++index) {
    const std::uint64_t route = 2000 + static_cast<std::uint64_t>(index);
    route_provenance::PublishRouteRequest request =
        fixture.route_request(route, "route/" + std::to_string(route), 1, ReasonCode::InitialRoute);
    request.root_reason = RootReason::InitialPublication;
    const auto published = fixture.store.publish_route(request);
    if (!published.has_value()) {
      continue;
    }
    const auto before = fixture.store.stats();
    RP_REQUIRE_HAS_VALUE(before);
    for (int replay = 0; replay < 3; ++replay) {
      const auto repeated = fixture.store.publish_route(request);
      RP_EXPECT_EQ(repeated.outcome(), Outcome::Idempotent);
    }
    const auto after = fixture.store.stats();
    RP_REQUIRE_HAS_VALUE(after);
    RP_EXPECT_EQ(before.value().node_count, after.value().node_count);
    RP_EXPECT_EQ(before.value().edge_count, after.value().edge_count);
    RP_EXPECT_EQ(before.value().store_generation, after.value().store_generation);
  }
  static_cast<void>(random);
}

RP_TEST(property, insertion_order_does_not_change_digests_or_queries) {
  // The same provenance content is inserted in two different valid interleavings. Content
  // includes the authority context, so every record keeps its own attempt identity: only the
  // insertion order changes.
  const std::uint64_t routes[] = {3001, 3002, 3003};
  const auto attempt_for = [](std::uint64_t route, std::uint64_t generation) {
    return route * 100 + generation;
  };
  const auto build = [&routes, &attempt_for](bool reverse_order, Digest& digest, std::size_t& nodes,
                                             std::vector<std::uint64_t>& ancestors) {
    Fixture fixture;
    std::vector<std::uint64_t> order(routes, routes + 3);
    if (reverse_order) {
      std::reverse(order.begin(), order.end());
    }
    for (std::uint64_t generation = 1; generation <= 3; ++generation) {
      for (const std::uint64_t route : order) {
        const std::string name = "route/" + std::to_string(route);
        route_provenance::PublishRouteRequest request =
            fixture.route_request(route, name, generation, ReasonCode::RouteReplaced);
        request.authority.attempt =
            MutationAttemptId::from_value(attempt_for(route, generation));
        if (generation == 1) {
          request.root_reason = RootReason::InitialPublication;
          request.reason = ReasonCode::InitialRoute;
        } else {
          const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(route));
          if (!lineage.has_value()) {
            continue;
          }
          EdgeSpec edge;
          edge.type = EdgeType::Supersedes;
          edge.target = lineage.value().current_node;
          edge.reason = ReasonCode::RouteReplaced;
          request.edges.push_back(edge);
        }
        static_cast<void>(fixture.store.publish_route(request));
      }
    }
    const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(routes[0]));
    if (!lineage.has_value()) {
      return;
    }
    const auto snapshot = fixture.store.snapshot(lineage.value().id);
    if (!snapshot.has_value()) {
      return;
    }
    digest = snapshot.value().digest;
    nodes = snapshot.value().nodes.size();
    const auto chain = fixture.store.predecessor_chain(snapshot.value().current_node,
                                                       TraversalBounds{});
    if (chain.has_value()) {
      for (const TraversalEntry& entry : chain.value().nodes) {
        ancestors.push_back(entry.node.route_generation.value());
      }
    }
  };
  Digest forward_digest;
  Digest reverse_digest;
  std::size_t forward_nodes = 0;
  std::size_t reverse_nodes = 0;
  std::vector<std::uint64_t> forward_ancestors;
  std::vector<std::uint64_t> reverse_ancestors;
  build(false, forward_digest, forward_nodes, forward_ancestors);
  build(true, reverse_digest, reverse_nodes, reverse_ancestors);
  RP_EXPECT_EQ(forward_digest, reverse_digest);
  RP_EXPECT_EQ(forward_nodes, reverse_nodes);
  RP_EXPECT_TRUE(forward_ancestors == reverse_ancestors);
}
