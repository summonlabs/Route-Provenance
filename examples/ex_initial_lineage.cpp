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
  std::cout << "example=initial_lineage version=" << kVersionString << "\n";
  Example example;
  const Result<Publication> root =
      example.publish(101, "example/initial", 1, ReasonCode::InitialRoute,
                      RootReason::InitialPublication);
  if (report("initial", root.outcome()) != 0) {
    return 1;
  }
  step("route=101 generation=1 reason=INITIAL_ROUTE root=INITIAL_PUBLICATION");

  const Result<LineageView> lineage =
      example.store.lineage_for_route(RouteId::from_value(101));
  if (!lineage.has_value()) {
    return 1;
  }
  std::cout << "lineage=" << lineage.value().id.to_string()
            << " current_generation=" << lineage.value().current_route_generation.to_string()
            << " currentness=" << to_string(lineage.value().current_currentness) << "\n";
  const Result<Snapshot> snapshot = example.store.snapshot(lineage.value().id);
  if (!snapshot.has_value()) {
    return 1;
  }
  std::cout << "snapshot_nodes=" << snapshot.value().nodes.size()
            << " digest=" << snapshot.value().digest.hex() << "\n";
  return 0;
}
