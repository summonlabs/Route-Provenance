// Route Provenance - deterministic race suite.
//
// Races are forced with explicit barriers rather than sleeps. Every barrier wait is bounded and
// reports an explicit failure when the bound is exceeded, so a stuck system fails instead of
// hanging.
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "harness.hpp"
#include "route_provenance/persistence.hpp"
#include "support.hpp"

using namespace rp_test;
using namespace route_provenance;

namespace {

/// Rendezvous point with a bounded wait: exceeding the budget is a failure, never a hang.
class Barrier {
 public:
  explicit Barrier(std::size_t parties) : parties_(parties), waiting_(0), generation_(0) {}

  [[nodiscard]] bool arrive_and_wait(unsigned milliseconds) {
    std::unique_lock<std::mutex> lock(mutex_);
    const std::size_t generation = generation_;
    if (++waiting_ == parties_) {
      ++generation_;
      waiting_ = 0;
      condition_.notify_all();
      return true;
    }
    return condition_.wait_for(lock, std::chrono::milliseconds(milliseconds),
                               [this, generation]() { return generation_ != generation; });
  }

 private:
  std::mutex mutex_;
  std::condition_variable condition_;
  std::size_t parties_;
  std::size_t waiting_;
  std::size_t generation_;
};

[[nodiscard]] Bindings path_bindings(std::uint64_t path, std::uint64_t generation) {
  Bindings bindings;
  PathBinding binding;
  binding.path = PathId::from_value(path);
  binding.generation = PathAuthorityGeneration::from_value(generation);
  binding.decision_digest = Digest::hash("race-path:" + std::to_string(path) + ":" +
                                         std::to_string(generation));
  bindings.path = binding;
  return bindings;
}

}  // namespace

RP_TEST(race, late_completion_cannot_become_current_after_route_advance) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(501, "route/race-one"));
  for (std::uint64_t generation = 2; generation <= 10; ++generation) {
    RP_REQUIRE_HAS_VALUE(
        fixture.publish_successor(501, "route/race-one", generation, ReasonCode::RouteReplaced));
  }
  const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(501));
  RP_REQUIRE_HAS_VALUE(lineage);
  RP_EXPECT_EQ(lineage.value().current_route_generation.value(), 10ULL);

  // The derivation for generation 10 begins here.
  route_provenance::PublishRouteRequest request =
      fixture.route_request(501, "route/race-one", 10, ReasonCode::RouteReplaced);
  EdgeSpec edge;
  edge.type = EdgeType::Supersedes;
  edge.target = lineage.value().current_node;
  request.edges.push_back(edge);
  auto session = fixture.store.begin_publication(request);
  RP_REQUIRE_HAS_VALUE(session);

  // The route advances to generation 11 before the derivation completes.
  RP_REQUIRE_HAS_VALUE(
      fixture.publish_successor(501, "route/race-one", 11, ReasonCode::RouteReplaced));

  const auto committed = session.value().commit();
  RP_EXPECT_EQ(committed.outcome(), Outcome::StaleRoute);

  const auto after = fixture.store.lineage_for_route(RouteId::from_value(501));
  RP_REQUIRE_HAS_VALUE(after);
  RP_EXPECT_EQ(after.value().current_route_generation.value(), 11ULL);
  const auto current = fixture.store.node(after.value().current_node);
  RP_REQUIRE_HAS_VALUE(current);
  RP_EXPECT_EQ(current.value().route_generation.value(), 11ULL);
  RP_EXPECT_EQ(current.value().currentness, Currentness::Current);
}

RP_TEST(race, late_completion_cannot_become_present_authority_after_path_invalidation) {
  Fixture fixture;
  DependencyNotification path_notice;
  path_notice.kind = DependencyKind::PathAuthorityAdvance;
  path_notice.authority = fixture.context();
  path_notice.authority.scope = AuthorityScope::fabric();
  path_notice.path_authority_generation = PathAuthorityGeneration::from_value(7);
  RP_EXPECT_TRUE(!outcome_is_rejection(fixture.store.notify_dependency(path_notice).outcome()));

  RP_REQUIRE_HAS_VALUE(fixture.publish(511, "route/race-two", 1, ReasonCode::InitialRoute,
                                       RootReason::InitialPublication, std::vector<EdgeSpec>{},
                                       path_bindings(3, 7)));
  route_provenance::PublishRouteRequest request =
      fixture.route_request(511, "route/race-two", 2, ReasonCode::PathRevalidated);
  const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(511));
  RP_REQUIRE_HAS_VALUE(lineage);
  EdgeSpec edge;
  edge.type = EdgeType::Supersedes;
  edge.target = lineage.value().current_node;
  request.edges.push_back(edge);
  request.bindings = path_bindings(3, 7);

  auto session = fixture.store.begin_publication(request);
  RP_REQUIRE_HAS_VALUE(session);
  DependencyNotification advance = path_notice;
  advance.path_authority_generation = PathAuthorityGeneration::from_value(8);
  RP_EXPECT_TRUE(!outcome_is_rejection(fixture.store.notify_dependency(advance).outcome()));

  const auto committed = session.value().commit();
  RP_EXPECT_EQ(committed.outcome(), Outcome::StalePathAuthority);
  const auto after = fixture.store.lineage_for_route(RouteId::from_value(511));
  RP_REQUIRE_HAS_VALUE(after);
  RP_EXPECT_EQ(after.value().current_route_generation.value(), 1ULL);
}

RP_TEST(race, late_completion_cannot_survive_an_epoch_advance) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(521, "route/race-three"));
  const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(521));
  RP_REQUIRE_HAS_VALUE(lineage);
  route_provenance::PublishRouteRequest request =
      fixture.route_request(521, "route/race-three", 2, ReasonCode::RouteReplaced);
  EdgeSpec edge;
  edge.type = EdgeType::Supersedes;
  edge.target = lineage.value().current_node;
  request.edges.push_back(edge);
  auto session = fixture.store.begin_publication(request);
  RP_REQUIRE_HAS_VALUE(session);

  RP_EXPECT_TRUE(!outcome_is_rejection(
      fixture.store.advance_epoch(CoordinatorEpoch::from_value(2), fixture.context()).outcome()));
  const auto committed = session.value().commit();
  RP_EXPECT_EQ(committed.outcome(), Outcome::StaleEpoch);
}

RP_TEST(race, worker_fence_and_publication_are_serialised_deterministically) {
  for (int round = 0; round < 8; ++round) {
    Fixture fixture;
    RP_REQUIRE_HAS_VALUE(fixture.publish_root(531, "route/race-four"));
    const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(531));
    RP_REQUIRE_HAS_VALUE(lineage);

    Barrier barrier(2);
    std::atomic<bool> fenced{false};
    std::atomic<bool> published{false};
    Outcome publication_outcome = Outcome::Ok;

    std::thread fence_thread([&]() {
      if (!barrier.arrive_and_wait(10000)) {
        RP_FAIL("fence thread did not reach the rendezvous within the bound");
        return;
      }
      const Status status =
          fixture.store.fence_publisher(fixture.publisher, fixture.boot, fixture.context());
      fenced.store(!outcome_is_rejection(status.outcome()));
    });
    std::thread publish_thread([&]() {
      if (!barrier.arrive_and_wait(10000)) {
        RP_FAIL("publish thread did not reach the rendezvous within the bound");
        return;
      }
      route_provenance::PublishRouteRequest request =
          fixture.route_request(531, "route/race-four", 2, ReasonCode::RouteReplaced);
      EdgeSpec edge;
      edge.type = EdgeType::Supersedes;
      edge.target = lineage.value().current_node;
      request.edges.push_back(edge);
      const auto result = fixture.store.publish_route(request);
      publication_outcome = result.outcome();
      published.store(result.has_value());
    });
    fence_thread.join();
    publish_thread.join();

    RP_EXPECT_TRUE(fenced.load());
    // Either the publication committed before the fence, or it was refused afterwards. Both
    // outcomes are legal; a half-applied state is not.
    RP_EXPECT_TRUE(publication_outcome == Outcome::Created ||
                   publication_outcome == Outcome::StaleWorker);
    const auto after = fixture.store.lineage_for_route(RouteId::from_value(531));
    RP_REQUIRE_HAS_VALUE(after);
    const auto current = fixture.store.node(after.value().current_node);
    RP_REQUIRE_HAS_VALUE(current);
    if (publication_outcome == Outcome::Created) {
      RP_EXPECT_EQ(current.value().route_generation.value(), 2ULL);
      RP_EXPECT_EQ(current.value().currentness, Currentness::FencedPublisher);
    } else {
      RP_EXPECT_EQ(current.value().route_generation.value(), 1ULL);
      RP_EXPECT_EQ(current.value().currentness, Currentness::FencedPublisher);
    }
    // A fenced boot can never publish again, whatever the interleaving was.
    route_provenance::PublishRouteRequest blocked =
        fixture.route_request(531, "route/race-four", 3, ReasonCode::RouteReplaced);
    RP_EXPECT_EQ(fixture.store.publish_route(blocked).outcome(), Outcome::StaleWorker);
  }
}

RP_TEST(race, retirement_wins_against_a_racing_publication) {
  for (int round = 0; round < 8; ++round) {
    Fixture fixture;
    RP_REQUIRE_HAS_VALUE(fixture.publish_root(541, "route/race-five"));
    const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(541));
    RP_REQUIRE_HAS_VALUE(lineage);
    const ProvenanceNodeId target = lineage.value().current_node;

    Barrier barrier(2);
    Outcome publication_outcome = Outcome::Ok;
    std::thread retire_thread([&]() {
      if (!barrier.arrive_and_wait(10000)) {
        RP_FAIL("retire thread did not reach the rendezvous within the bound");
        return;
      }
      static_cast<void>(fixture.store.retire(
          fixture.administrative(541, "route/race-five", target, ReasonCode::Retirement)));
    });
    std::thread publish_thread([&]() {
      if (!barrier.arrive_and_wait(10000)) {
        RP_FAIL("publish thread did not reach the rendezvous within the bound");
        return;
      }
      route_provenance::PublishRouteRequest request =
          fixture.route_request(541, "route/race-five", 2, ReasonCode::RouteReplaced);
      EdgeSpec edge;
      edge.type = EdgeType::Supersedes;
      edge.target = target;
      request.edges.push_back(edge);
      publication_outcome = fixture.store.publish_route(request).outcome();
    });
    retire_thread.join();
    publish_thread.join();

    RP_EXPECT_TRUE(publication_outcome == Outcome::Created || publication_outcome == Outcome::Retired);
    const auto after = fixture.store.lineage_for_route(RouteId::from_value(541));
    RP_REQUIRE_HAS_VALUE(after);
    RP_EXPECT_EQ(after.value().lifecycle, LineageLifecycle::Retired);
    // Late publication after retirement never reactivates the lineage.
    route_provenance::PublishRouteRequest late =
        fixture.route_request(541, "route/race-five", 3, ReasonCode::RouteReplaced);
    RP_EXPECT_EQ(fixture.store.publish_route(late).outcome(), Outcome::Retired);
    const auto snapshot = fixture.store.snapshot(after.value().id);
    RP_REQUIRE_HAS_VALUE(snapshot);
    for (const ProvenanceNode& node : snapshot.value().nodes) {
      RP_EXPECT_NE(node.currentness, Currentness::Current);
    }
  }
}

RP_TEST(race, queries_during_correction_observe_consistent_state) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(551, "route/race-six"));
  const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(551));
  RP_REQUIRE_HAS_VALUE(lineage);
  const ProvenanceNodeId target = lineage.value().current_node;

  Barrier barrier(2);
  std::atomic<int> observations{0};
  std::thread correction_thread([&]() {
    if (!barrier.arrive_and_wait(10000)) {
      RP_FAIL("correction thread did not reach the rendezvous within the bound");
      return;
    }
    route_provenance::CorrectionRequest request;
    request.key = fixture.key(551, "route/race-six");
    request.target = target;
    request.authority = fixture.context();
    static_cast<void>(fixture.store.correct(request));
  });
  std::thread query_thread([&]() {
    if (!barrier.arrive_and_wait(10000)) {
      RP_FAIL("query thread did not reach the rendezvous within the bound");
      return;
    }
    for (int index = 0; index < 200; ++index) {
      const auto view = fixture.store.lineage_for_route(RouteId::from_value(551));
      if (!view.has_value()) {
        RP_FAIL("lineage query failed during correction");
        return;
      }
      const auto record = fixture.store.node(view.value().current_node);
      if (!record.has_value()) {
        RP_FAIL("current record missing during correction");
        return;
      }
      // The current record is either the original or the replacement, never a half state.
      if (record.value().lifecycle != NodeLifecycle::Current &&
          record.value().lifecycle != NodeLifecycle::Invalid) {
        RP_FAIL("observed an impossible lifecycle during correction");
        return;
      }
      observations.fetch_add(1);
    }
  });
  correction_thread.join();
  query_thread.join();
  RP_EXPECT_EQ(observations.load(), 200);
}

RP_TEST(race, persistence_snapshot_against_graph_mutation_is_consistent) {
  const std::string directory = make_temp_dir("snapshot-race", scratch_dir());
  const std::string path = directory + "/race.rpstore";
  for (int round = 0; round < 6; ++round) {
    Fixture fixture;
    RP_REQUIRE_HAS_VALUE(fixture.publish_root(561, "route/race-seven"));
    const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(561));
    RP_REQUIRE_HAS_VALUE(lineage);

    Barrier barrier(2);
    std::atomic<bool> saved{false};
    std::thread save_thread([&]() {
      if (!barrier.arrive_and_wait(10000)) {
        RP_FAIL("save thread did not reach the rendezvous within the bound");
        return;
      }
      const Status status = fixture.store.save(path);
      saved.store(status.outcome() == Outcome::Ok);
    });
    std::thread mutate_thread([&]() {
      if (!barrier.arrive_and_wait(10000)) {
        RP_FAIL("mutation thread did not reach the rendezvous within the bound");
        return;
      }
      for (std::uint64_t generation = 2; generation <= 5; ++generation) {
        static_cast<void>(
            fixture.publish_successor(561, "route/race-seven", generation, ReasonCode::RouteReplaced));
      }
    });
    save_thread.join();
    mutate_thread.join();
    RP_EXPECT_TRUE(saved.load());

    // Whatever the interleaving, the file must decode and describe a consistent lineage.
    const auto image = read_store_image(path, Limits::defaults());
    RP_REQUIRE_HAS_VALUE(image);
    RP_EXPECT_EQ(image.value().lineages.size(), 1U);
    ProvenanceStore restored;
    RP_EXPECT_TRUE(!outcome_is_rejection(restored.load(path).outcome()));
    const auto restored_lineage = restored.lineage(lineage.value().id);
    RP_REQUIRE_HAS_VALUE(restored_lineage);
    const auto snapshot = restored.snapshot(lineage.value().id);
    RP_REQUIRE_HAS_VALUE(snapshot);
    for (const ProvenanceNode& node : snapshot.value().nodes) {
      RP_EXPECT_TRUE(node.lineage == lineage.value().id);
    }
  }
}
