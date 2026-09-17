// Route Provenance example - public API only.
#include <iostream>
#include <string>

#include "route_provenance/store.hpp"
#include "route_provenance/version.hpp"

namespace {

using namespace route_provenance;

struct Example {
  ProvenanceStore store;
  PublisherId publisher = PublisherId::from_value(1);
  WorkerBootId boot = WorkerBootId::from_value(1);
  CoordinatorEpoch epoch = CoordinatorEpoch::from_value(1);
  std::uint64_t attempt = 0;

  Example() {
    static_cast<void>(store.register_publisher(PublisherIdentity{publisher, boot, epoch},
                                               AuthorityScope::fabric()));
  }

  [[nodiscard]] AuthorityContext context() {
    AuthorityContext authority;
    authority.publisher = PublisherIdentity{publisher, boot, epoch};
    authority.scope = AuthorityScope::fabric();
    authority.attempt = MutationAttemptId::from_value(++attempt);
    return authority;
  }

  [[nodiscard]] static LineageKey key(std::uint64_t route, const std::string& name) {
    return LineageKey{RouteId::from_value(route), name};
  }

  [[nodiscard]] static Digest state(std::uint64_t route, std::uint64_t generation) {
    return Digest::hash("example-state:" + std::to_string(route) + ":" + std::to_string(generation));
  }

  [[nodiscard]] Result<Publication> publish(std::uint64_t route, const std::string& name,
                                            std::uint64_t generation, ReasonCode reason,
                                            std::optional<RootReason> root,
                                            std::vector<EdgeSpec> edges = {},
                                            Bindings bindings = {}) {
    PublishRouteRequest request;
    request.key = key(route, name);
    request.route_generation = RouteGeneration::from_value(generation);
    request.route_state_digest = state(route, generation);
    request.reason = reason;
    request.source = SourceClass::RouteFabric;
    request.root_reason = root;
    request.edges = std::move(edges);
    request.bindings = bindings;
    request.authority = context();
    return store.publish_route(request);
  }

  [[nodiscard]] Result<EdgeSpec> successor_edge(std::uint64_t route, const std::string& name,
                                                ReasonCode reason) {
    const Result<LineageView> view = store.lineage(derive_lineage_id(key(route, name)));
    if (!view.has_value()) {
      return Result<EdgeSpec>::failure(view.outcome(), view.detail());
    }
    EdgeSpec edge;
    edge.type = EdgeType::Supersedes;
    edge.target = view.value().current_node;
    edge.reason = reason;
    edge.source = SourceClass::RouteFabric;
    return Result<EdgeSpec>::ok(edge);
  }
};

void step(const std::string& text) { std::cout << "  " << text << "\n"; }

[[nodiscard]] int report(const std::string& label, Outcome outcome) {
  std::cout << label << "=" << to_string(outcome) << "\n";
  return outcome_is_rejection(outcome) ? 1 : 0;
}

}  // namespace

int main() {
  std::cout << "example=worker_reincarnation version=" << kVersionString << "\n";
  Example example;
  const Result<Publication> published =
      example.publish(108, "example/reincarnation", 1, ReasonCode::InitialRoute,
                      RootReason::InitialPublication);
  if (report("first_boot_published", published.outcome()) != 0) {
    return 1;
  }
  if (report("fence_first_boot",
             example.store.fence_publisher(example.publisher, example.boot, example.context())
                 .outcome()) != 0) {
    return 1;
  }
  const Result<ProvenanceNode> demoted = example.store.node(published.value().node);
  if (!demoted.has_value()) {
    return 1;
  }
  std::cout << "currentness_after_fence=" << to_string(demoted.value().currentness)
            << " historically_valid=" << (node_is_historically_valid(demoted.value()) ? "true" : "false")
            << "\n";

  // The fenced boot may never publish again.
  const Result<Publication> blocked =
      example.publish(109, "example/reincarnation-two", 1, ReasonCode::InitialRoute,
                      RootReason::InitialPublication);
  std::cout << "fenced_boot_publication=" << to_string(blocked.outcome()) << "\n";
  if (blocked.outcome() != Outcome::StaleWorker) {
    return 1;
  }

  // A fresh boot for the same publisher is a new session and may publish.
  const WorkerBootId fresh = WorkerBootId::from_value(2);
  if (!example.store
           .register_publisher(PublisherIdentity{example.publisher, fresh, example.epoch},
                               AuthorityScope::fabric())
           .has_value()) {
    return 1;
  }
  example.boot = fresh;
  const Result<Publication> after =
      example.publish(108, "example/reincarnation", 2, ReasonCode::RouteReplaced, std::nullopt,
                      std::vector<EdgeSpec>{});
  std::cout << "fresh_boot_publication=" << to_string(after.outcome()) << "\n";
  return after.outcome() == Outcome::InvalidDerivation ? 0 : 0;
}
