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
  std::cout << "example=historical_currentness version=" << kVersionString << "\n";
  Example example;
  DependencyNotification path;
  path.kind = DependencyKind::PathAuthorityAdvance;
  path.path_authority_generation = PathAuthorityGeneration::from_value(12);
  path.authority = example.context();
  static_cast<void>(example.store.notify_dependency(path));

  Bindings bindings;
  PathBinding binding;
  binding.path = PathId::from_value(5);
  binding.generation = PathAuthorityGeneration::from_value(12);
  binding.decision_digest = Digest::hash("path-decision:5:12");
  bindings.path = binding;
  const Result<Publication> published =
      example.publish(107, "example/historical", 7, ReasonCode::InitialRoute,
                      RootReason::InitialPublication, {}, bindings);
  if (report("generation_seven_authorized", published.outcome()) != 0) {
    return 1;
  }

  DependencyNotification supersede = path;
  supersede.path_authority_generation = PathAuthorityGeneration::from_value(13);
  static_cast<void>(example.store.notify_dependency(supersede));

  const Result<ProvenanceNode> record = example.store.node(published.value().node);
  if (!record.has_value()) {
    return 1;
  }
  std::cout << "lifecycle=" << to_string(record.value().lifecycle)
            << " currentness=" << to_string(record.value().currentness)
            << " historically_valid=" << (node_is_historically_valid(record.value()) ? "true" : "false")
            << " current=" << (record.value().currentness == Currentness::Current ? "true" : "false")
            << "\n";
  ExplainRequest request;
  request.subject = record.value().id;
  request.mode = ExplainMode::PathOnly;
  const Result<Explanation> explanation = example.store.explain(request);
  if (!explanation.has_value()) {
    return 1;
  }
  std::cout << "explanation_historical=" << (explanation.value().historically_valid ? "true" : "false")
            << " explanation_current=" << (explanation.value().current ? "true" : "false") << "\n";
  return 0;
}
