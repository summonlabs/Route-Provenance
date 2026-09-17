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
  std::cout << "example=supersession version=" << kVersionString << "\n";
  Example example;
  if (report("initial",
             example.publish(102, "example/supersede", 1, ReasonCode::InitialRoute,
                             RootReason::InitialPublication)
                 .outcome()) != 0) {
    return 1;
  }
  const Result<EdgeSpec> edge =
      example.successor_edge(102, "example/supersede", ReasonCode::RouteReplaced);
  if (!edge.has_value()) {
    return 1;
  }
  const Result<Publication> replacement =
      example.publish(102, "example/supersede", 2, ReasonCode::RouteReplaced, std::nullopt,
                      std::vector<EdgeSpec>{edge.value()});
  if (report("supersede", replacement.outcome()) != 0) {
    return 1;
  }
  const Result<ProvenanceNode> previous =
      example.store.route_node(RouteId::from_value(102), RouteGeneration::from_value(1));
  if (!previous.has_value()) {
    return 1;
  }
  std::cout << "predecessor_lifecycle=" << to_string(previous.value().lifecycle)
            << " currentness=" << to_string(previous.value().currentness)
            << " historically_valid=" << (node_is_historically_valid(previous.value()) ? "true" : "false")
            << "\n";
  const Result<TraversalResult> chain =
      example.store.predecessor_chain(replacement.value().node, TraversalBounds{});
  if (!chain.has_value()) {
    return 1;
  }
  std::cout << "chain_length=" << chain.value().nodes.size() << "\n";
  return 0;
}
