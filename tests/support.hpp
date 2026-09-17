// Route Provenance - shared test fixtures.
//
// Fixtures build requests through the public API only. They never reach into the runtime's
// internals, so a test that passes here proves the same behaviour a consumer would observe.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "route_provenance/store.hpp"
#include "route_provenance/version.hpp"

namespace rp_test {

using route_provenance::AuthorityContext;
using route_provenance::AuthorityScope;
using route_provenance::Bindings;
using route_provenance::CoordinatorEpoch;
using route_provenance::Digest;
using route_provenance::EdgeSpec;
using route_provenance::EdgeType;
using route_provenance::EvidenceEntry;
using route_provenance::EvidenceField;
using route_provenance::EvidenceVector;
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

/// Test fixture: one store with a registered fabric-scoped coordinator publisher.
struct Fixture {
  Limits limits = Limits::defaults();
  ProvenanceStore store;
  PublisherId publisher = PublisherId::from_value(1);
  WorkerBootId boot = WorkerBootId::from_value(1);
  CoordinatorEpoch epoch = CoordinatorEpoch::from_value(1);
  AuthorityScope scope = AuthorityScope::fabric();
  std::uint64_t attempt = 0;

  explicit Fixture(Limits store_limits = Limits::defaults())
      : limits(store_limits), store(store_limits) {
    static_cast<void>(store.register_publisher(PublisherIdentity{publisher, boot, epoch}, scope));
  }

  [[nodiscard]] MutationAttemptId next_attempt() {
    return MutationAttemptId::from_value(++attempt);
  }

  [[nodiscard]] AuthorityContext context() {
    AuthorityContext authority;
    authority.publisher = PublisherIdentity{publisher, boot, epoch};
    authority.scope = scope;
    authority.attempt = next_attempt();
    return authority;
  }

  [[nodiscard]] AuthorityContext context(AuthorityScope target) {
    AuthorityContext authority = context();
    authority.scope = target;
    return authority;
  }

  [[nodiscard]] AuthorityContext other_context(PublisherId other_publisher, WorkerBootId other_boot,
                                               CoordinatorEpoch other_epoch) {
    AuthorityContext authority;
    authority.publisher = PublisherIdentity{other_publisher, other_boot, other_epoch};
    authority.scope = AuthorityScope::fabric();
    authority.attempt = next_attempt();
    return authority;
  }

  [[nodiscard]] LineageKey key(std::uint64_t route, const std::string& name) const {
    LineageKey lineage_key;
    lineage_key.route = RouteId::from_value(route);
    lineage_key.semantic_key = name;
    return lineage_key;
  }

  [[nodiscard]] static Digest state_digest(std::uint64_t route, std::uint64_t generation) {
    return Digest::hash("test-route-state:" + std::to_string(route) + ":" +
                        std::to_string(generation));
  }

  [[nodiscard]] route_provenance::PublishRouteRequest route_request(std::uint64_t route,
                                                                   const std::string& name,
                                                                   std::uint64_t generation,
                                                                   ReasonCode reason) {
    route_provenance::PublishRouteRequest request;
    request.key = key(route, name);
    request.route_generation = RouteGeneration::from_value(generation);
    request.route_state_digest = state_digest(route, generation);
    request.reason = reason;
    request.source = SourceClass::RouteFabric;
    request.authority = context();
    return request;
  }

  [[nodiscard]] route_provenance::Result<route_provenance::Publication> publish(
      std::uint64_t route, const std::string& name, std::uint64_t generation, ReasonCode reason,
      std::optional<RootReason> root = std::nullopt,
      std::vector<EdgeSpec> edges = std::vector<EdgeSpec>{}, Bindings bindings = Bindings{}) {
    route_provenance::PublishRouteRequest request = route_request(route, name, generation, reason);
    request.root_reason = root;
    request.edges = std::move(edges);
    request.bindings = bindings;
    return store.publish_route(request);
  }

  /// Publishes the initial generation of a lineage as an explicit root.
  [[nodiscard]] route_provenance::Result<route_provenance::Publication> publish_root(
      std::uint64_t route, const std::string& name) {
    return publish(route, name, 1, ReasonCode::InitialRoute, RootReason::InitialPublication);
  }

  /// Publishes a successor generation that supersedes the current record.
  [[nodiscard]] route_provenance::Result<route_provenance::Publication> publish_successor(
      std::uint64_t route, const std::string& name, std::uint64_t generation, ReasonCode reason,
      Bindings bindings = Bindings{}) {
    const route_provenance::Result<route_provenance::LineageView> view =
        store.lineage(route_provenance::derive_lineage_id(key(route, name)));
    if (!view.has_value() || !view.value().current_node.valid()) {
      return route_provenance::Result<route_provenance::Publication>::failure(
          Outcome::LineageNotFound, "fixture could not resolve the current record");
    }
    EdgeSpec edge;
    edge.type = EdgeType::Supersedes;
    edge.target = view.value().current_node;
    edge.reason = reason;
    edge.source = SourceClass::RouteFabric;
    std::vector<EdgeSpec> edges;
    edges.push_back(edge);
    return publish(route, name, generation, reason, std::nullopt, std::move(edges), bindings);
  }

  [[nodiscard]] route_provenance::Result<route_provenance::ProvenanceNode> current_node(
      std::uint64_t route, const std::string& name) {
    const route_provenance::Result<route_provenance::LineageView> view =
        store.lineage(route_provenance::derive_lineage_id(key(route, name)));
    if (!view.has_value()) {
      return route_provenance::Result<route_provenance::ProvenanceNode>::failure(
          view.outcome(), view.detail());
    }
    return store.node(view.value().current_node);
  }

  [[nodiscard]] route_provenance::AdministrativeRequest administrative(
      std::uint64_t route, const std::string& name, route_provenance::ProvenanceNodeId target,
      ReasonCode reason) {
    route_provenance::AdministrativeRequest request;
    request.key = key(route, name);
    request.target = target;
    request.reason = reason;
    request.source = SourceClass::Administrative;
    request.authority = context();
    request.allow_non_current_target = true;
    return request;
  }

  [[nodiscard]] route_provenance::DeclarationRequest declaration(std::uint64_t route,
                                                                const std::string& name,
                                                                route_provenance::NodeKind kind) {
    route_provenance::DeclarationRequest request;
    request.key = key(route, name);
    request.kind = kind;
    request.source = SourceClass::PathAuthority;
    request.authority = context();
    return request;
  }
};

/// Deterministic seeded generator used by the property and scale suites.
class SeededRandom {
 public:
  explicit SeededRandom(std::uint64_t seed) : state_(seed == 0 ? 0x9E3779B97F4A7C15ULL : seed) {}

  [[nodiscard]] std::uint64_t next() {
    state_ ^= state_ << 13U;
    state_ ^= state_ >> 7U;
    state_ ^= state_ << 17U;
    return state_;
  }

  [[nodiscard]] std::uint64_t below(std::uint64_t bound) { return bound == 0 ? 0 : next() % bound; }

  [[nodiscard]] std::uint64_t seed() const noexcept { return state_; }

 private:
  std::uint64_t state_;
};

}  // namespace rp_test
