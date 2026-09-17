// Route Provenance - benchmark harness.
//
// Every figure reported here measures completed operations. Timings are machine specific
// observations, not guarantees. The workload is synthetic.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

#include "route_provenance/store.hpp"
#include "route_provenance/version.hpp"

namespace {

using route_provenance::AuthorityScope;
using route_provenance::CoordinatorEpoch;
using route_provenance::Digest;
using route_provenance::EdgeSpec;
using route_provenance::EdgeType;
using route_provenance::LineageKey;
using route_provenance::Limits;
using route_provenance::MutationAttemptId;
using route_provenance::Outcome;
using route_provenance::ProvenanceStore;
using route_provenance::PublisherId;
using route_provenance::PublisherIdentity;
using route_provenance::ReasonCode;
using route_provenance::RootReason;
using route_provenance::RouteGeneration;
using route_provenance::RouteId;
using route_provenance::SourceClass;
using route_provenance::WorkerBootId;

class Stopwatch {
 public:
  Stopwatch() : start_(std::chrono::steady_clock::now()) {}

  [[nodiscard]] double milliseconds() const {
    const auto elapsed = std::chrono::steady_clock::now() - start_;
    return std::chrono::duration<double, std::milli>(elapsed).count();
  }

 private:
  std::chrono::steady_clock::time_point start_;
};

struct Bench {
  Limits limits = Limits::defaults();
  ProvenanceStore store;
  PublisherId publisher = PublisherId::from_value(1);
  WorkerBootId boot = WorkerBootId::from_value(1);
  CoordinatorEpoch epoch = CoordinatorEpoch::from_value(1);
  std::uint64_t attempt = 0;

  Bench() : store(limits) {
    static_cast<void>(store.register_publisher(PublisherIdentity{publisher, boot, epoch},
                                               AuthorityScope::fabric()));
  }

  [[nodiscard]] route_provenance::PublishRouteRequest request(std::uint64_t route,
                                                              const std::string& name,
                                                              std::uint64_t generation,
                                                              ReasonCode reason) {
    route_provenance::PublishRouteRequest request;
    request.key = LineageKey{RouteId::from_value(route), name};
    request.route_generation = RouteGeneration::from_value(generation);
    request.route_state_digest = Digest::hash("bench:" + std::to_string(route) + ":" +
                                              std::to_string(generation));
    request.reason = reason;
    request.source = SourceClass::RouteFabric;
    request.authority.publisher = PublisherIdentity{publisher, boot, epoch};
    request.authority.scope = AuthorityScope::fabric();
    request.authority.attempt = MutationAttemptId::from_value(++attempt);
    return request;
  }
};

void report(const std::string& name, std::uint64_t operations, double milliseconds) {
  const double per_operation = operations == 0 ? 0.0 : milliseconds / static_cast<double>(operations);
  std::cout << "bench name=" << name << " operations=" << operations
            << " total_ms=" << static_cast<std::uint64_t>(milliseconds)
            << " us_per_operation=" << static_cast<std::uint64_t>(per_operation * 1000.0) << "\n";
}

}  // namespace

int main(int argc, char** argv) {
  bool small = false;
  for (int index = 1; index < argc; ++index) {
    if (std::string(argv[index]) == "--small") {
      small = true;
    }
  }
  const std::uint64_t lineage_count = small ? 1000 : 100000;
  const std::uint64_t chain_length = small ? 64 : 1000;

  std::cout << "product=" << route_provenance::kProductName
            << " version=" << route_provenance::kVersionString << " mode=" << (small ? "small" : "full")
            << "\n";

  // Publication throughput.
  {
    Bench bench;
    const Stopwatch watch;
    std::uint64_t completed = 0;
    for (std::uint64_t index = 0; index < lineage_count; ++index) {
      route_provenance::PublishRouteRequest request =
          bench.request(1000 + index, "bench/route-" + std::to_string(index), 1,
                        ReasonCode::InitialRoute);
      request.root_reason = RootReason::InitialPublication;
      if (bench.store.publish_route(request).has_value()) {
        ++completed;
      }
    }
    report("publication_initial", completed, watch.milliseconds());
  }

  // Supersession chain publication and explanation of a deep chain.
  {
    Bench bench;
    const std::uint64_t route = 777;
    route_provenance::PublishRouteRequest root =
        bench.request(route, "bench/chain", 1, ReasonCode::InitialRoute);
    root.root_reason = RootReason::InitialPublication;
    static_cast<void>(bench.store.publish_route(root));
    const Stopwatch watch;
    std::uint64_t completed = 0;
    for (std::uint64_t generation = 2; generation <= chain_length; ++generation) {
      const auto lineage = bench.store.lineage(route_provenance::derive_lineage_id(
          LineageKey{RouteId::from_value(route), "bench/chain"}));
      if (!lineage.has_value()) {
        break;
      }
      route_provenance::PublishRouteRequest request =
          bench.request(route, "bench/chain", generation, ReasonCode::RouteReplaced);
      EdgeSpec edge;
      edge.type = EdgeType::Supersedes;
      edge.target = lineage.value().current_node;
      edge.reason = ReasonCode::RouteReplaced;
      request.edges.push_back(edge);
      if (bench.store.publish_route(request).has_value()) {
        ++completed;
      }
    }
    report("publication_supersession", completed, watch.milliseconds());

    const auto lineage = bench.store.lineage(
        route_provenance::derive_lineage_id(LineageKey{RouteId::from_value(route), "bench/chain"}));
    if (lineage.has_value()) {
      const Stopwatch explanation_watch;
      const route_provenance::ExplainRequest explain{lineage.value().current_node,
                                                     route_provenance::ExplainMode::FullAncestry, 0, 0};
      const auto explanation = bench.store.explain(explain);
      report("explanation_deep_chain", explanation.has_value() ? explanation.value().steps.size() : 0,
             explanation_watch.milliseconds());

      const Stopwatch ancestry_watch;
      const auto ancestors = bench.store.ancestors(lineage.value().current_node,
                                                   route_provenance::TraversalBounds{});
      report("ancestry_query", ancestors.has_value() ? ancestors.value().nodes.size() : 0,
             ancestry_watch.milliseconds());

      const Stopwatch digest_watch;
      static_cast<void>(bench.store.snapshot(lineage.value().id));
      report("snapshot_and_digest", 1, digest_watch.milliseconds());
    }
  }

  // Reverse index lookup at scale.
  {
    Bench bench;
    std::uint64_t completed = 0;
    for (std::uint64_t index = 0; index < lineage_count; ++index) {
      route_provenance::PublishRouteRequest request =
          bench.request(5000 + index, "bench/indexed-" + std::to_string(index), 1,
                        ReasonCode::InitialRoute);
      request.root_reason = RootReason::InitialPublication;
      request.bindings.path = route_provenance::PathBinding{
          route_provenance::PathId::from_value(900 + (index % 50)),
          route_provenance::PathAuthorityGeneration::from_value(1), Digest::hash("path")};
      if (bench.store.publish_route(request).has_value()) {
        ++completed;
      }
    }
    const Stopwatch watch;
    const auto derived = bench.store.routes_derived_from_path(route_provenance::PathId::from_value(900),
                                                              route_provenance::TraversalBounds{0, 0, 0});
    report("path_reverse_lookup", derived.has_value() ? derived.value().size() : completed,
           watch.milliseconds());
  }

  // Persistence save and load.
  {
    Bench bench;
    for (std::uint64_t index = 0; index < (small ? 2000U : 20000U); ++index) {
      route_provenance::PublishRouteRequest request =
          bench.request(9000 + index, "bench/persist-" + std::to_string(index), 1,
                        ReasonCode::InitialRoute);
      request.root_reason = RootReason::InitialPublication;
      static_cast<void>(bench.store.publish_route(request));
    }
    const std::string path = std::string(RP_BENCH_SCRATCH_FILE);
    const Stopwatch save_watch;
    const auto saved = bench.store.save(path);
    report("persistence_save", saved.outcome() == Outcome::Ok ? 1 : 0, save_watch.milliseconds());
    const Stopwatch load_watch;
    ProvenanceStore restored;
    const auto loaded = restored.load(path);
    report("persistence_load", route_provenance::outcome_is_rejection(loaded.outcome()) ? 0 : 1,
           load_watch.milliseconds());
  }

  // Population of 100k lineages, reported as one completed operation per lineage.
  if (!small) {
    Bench bench;
    const Stopwatch watch;
    std::uint64_t completed = 0;
    for (std::uint64_t index = 0; index < 100000; ++index) {
      route_provenance::PublishRouteRequest request =
          bench.request(100000 + index, "bench/pop-" + std::to_string(index), 1,
                        ReasonCode::InitialRoute);
      request.root_reason = RootReason::InitialPublication;
      if (bench.store.publish_route(request).has_value()) {
        ++completed;
      }
    }
    report("population_100k_lineages", completed, watch.milliseconds());
    const Stopwatch stats_watch;
    static_cast<void>(bench.store.stats());
    report("statistics_pass", completed, stats_watch.milliseconds());
  }
  return 0;
}
