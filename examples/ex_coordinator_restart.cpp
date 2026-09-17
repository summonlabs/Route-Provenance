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

#include <cstdio>

#include "route_provenance/runtime.hpp"

int main() {
  std::cout << "example=coordinator_restart version=" << kVersionString << "\n";
  const std::string path = "example-coordinator-restart.rpstore";
  const RouteLineageId lineage =
      derive_lineage_id(LineageKey{RouteId::from_value(110), "example/restart"});

  {
    Example example;
    if (report("initial",
               example.publish(110, "example/restart", 1, ReasonCode::InitialRoute,
                               RootReason::InitialPublication)
                   .outcome()) != 0) {
      return 1;
    }
    const Result<EdgeSpec> edge =
        example.successor_edge(110, "example/restart", ReasonCode::RouteReplaced);
    if (!edge.has_value() ||
        report("second_generation",
               example.publish(110, "example/restart", 2, ReasonCode::RouteReplaced, std::nullopt,
                               std::vector<EdgeSpec>{edge.value()})
                   .outcome()) != 0) {
      return 1;
    }
    // The coordinator session is served by the runtime's own server and client types.
    ServerOptions server_options;
    server_options.client_scope = AuthorityScope::fabric();
    server_options.coordinator_authority = example.context();
    ProvenanceServer server(example.store, server_options);
    std::string error;
    if (!server.start(error).is_ok()) {
      std::cerr << "server start failed: " << error << "\n";
      return 1;
    }
    ClientOptions client_options;
    client_options.port = server.port();
    ProvenanceClient client(client_options);
    if (!client.connect(error).is_ok()) {
      std::cerr << "client connect failed: " << error << "\n";
      return 1;
    }
    RegistrationPayload registration;
    registration.identity =
        PublisherIdentity{PublisherId::from_value(500), WorkerBootId::from_value(500), example.epoch};
    registration.scope = AuthorityScope::fabric();
    const Result<HelloAckPayload> ack = client.hello(registration);
    if (!ack.has_value() || !ack.value().accepted) {
      std::cerr << "registration refused\n";
      return 1;
    }
    const Result<LineageView> view = client.query_lineage(lineage);
    if (!view.has_value()) {
      return 1;
    }
    std::cout << "live_lineage_nodes=" << view.value().node_count
              << " currentness=" << to_string(view.value().current_currentness) << "\n";
    client.close();
    static_cast<void>(server.stop());
    if (example.store.save(path).outcome() != Outcome::Ok) {
      return 1;
    }
  }

  {
    // A restart consumes a higher epoch and requires explicit revalidation.
    ProvenanceStore reopened;
    if (outcome_is_rejection(reopened.load(path).outcome())) {
      return 1;
    }
    const Result<LineageView> recovered = reopened.lineage(lineage);
    if (!recovered.has_value()) {
      return 1;
    }
    std::cout << "recovered_nodes=" << recovered.value().node_count
              << " current_generation=" << recovered.value().current_route_generation.to_string()
              << " currentness=" << to_string(recovered.value().current_currentness) << "\n";
    const Result<DependencyWatermarks> marks = reopened.watermarks();
    if (!marks.has_value()) {
      return 1;
    }
    std::cout << "recovered_epoch=" << marks.value().epoch.to_string() << "\n";
  }
  static_cast<void>(std::remove(path.c_str()));
  return 0;
}
