// Route Provenance - publication authority provenance.
//
// A publisher identity without boot and epoch context is insufficient. Every authoritative
// publication binds PublisherId, WorkerBootId, CoordinatorEpoch, an explicit authority scope
// and a MutationAttemptId. Connected is not authoritative; persisted is not live.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "route_provenance/digest.hpp"
#include "route_provenance/id.hpp"
#include "route_provenance/result.hpp"

namespace route_provenance {

/// Identity of a live publication session.
struct PublisherIdentity {
  PublisherId publisher;
  WorkerBootId boot;
  CoordinatorEpoch epoch;

  [[nodiscard]] bool valid() const noexcept { return publisher.valid() && boot.valid() && epoch.valid(); }
  friend bool operator==(const PublisherIdentity&, const PublisherIdentity&) noexcept = default;
  friend std::strong_ordering operator<=>(const PublisherIdentity&, const PublisherIdentity&) noexcept = default;
  [[nodiscard]] std::string describe() const;
};

/// What a publication attempt is allowed to touch.
struct ScopeTarget {
  RoutingNamespaceId routing_namespace;
  RouteLineageId lineage;
  RouteId route;
};

enum class ScopeKind : std::uint16_t {
  None = 0,
  Fabric = 1,
  RoutingNamespace = 2,
  Lineage = 3,
  Route = 4,
};

[[nodiscard]] std::string_view to_string(ScopeKind kind) noexcept;
[[nodiscard]] std::optional<ScopeKind> parse_scope_kind(std::string_view text) noexcept;

/// Explicit authority scope. The default-constructed scope is empty and permits nothing:
/// global provenance publication is never implicit.
class AuthorityScope {
 public:
  AuthorityScope() = default;

  [[nodiscard]] static AuthorityScope none() noexcept { return AuthorityScope{}; }
  [[nodiscard]] static AuthorityScope fabric() noexcept;
  [[nodiscard]] static AuthorityScope routing_namespace(RoutingNamespaceId id) noexcept;
  [[nodiscard]] static AuthorityScope lineage(RouteLineageId id) noexcept;
  [[nodiscard]] static AuthorityScope route(RouteId id) noexcept;

  [[nodiscard]] ScopeKind kind() const noexcept { return kind_; }
  [[nodiscard]] std::uint64_t subject() const noexcept { return subject_; }
  [[nodiscard]] bool is_empty() const noexcept { return kind_ == ScopeKind::None; }

  /// Default deny. Returns true only when this scope explicitly covers the target.
  [[nodiscard]] bool permits(const ScopeTarget& target) const noexcept;

  [[nodiscard]] std::string describe() const;
  void encode(CanonicalEncoder& encoder, std::uint16_t field) const;

  friend bool operator==(const AuthorityScope&, const AuthorityScope&) noexcept = default;
  friend std::strong_ordering operator<=>(const AuthorityScope&, const AuthorityScope&) noexcept = default;

 private:
  ScopeKind kind_ = ScopeKind::None;
  std::uint64_t subject_ = 0;
};

/// Full authority context of one publication attempt.
struct AuthorityContext {
  PublisherIdentity publisher;
  AuthorityScope scope;
  MutationAttemptId attempt;
  /// Optional optimistic-concurrency expectations. When present they are checked against the
  /// live lineage/store generation and produce a stale outcome on mismatch.
  std::optional<LineageGeneration> expected_lineage_generation;
  std::optional<ProvenanceGeneration> expected_provenance_generation;

  [[nodiscard]] bool has_identity() const noexcept { return publisher.valid() && attempt.valid(); }
  void encode(CanonicalEncoder& encoder, std::uint16_t field) const;
  [[nodiscard]] Digest digest() const noexcept;
};

/// A registered publisher session as tracked by a store or coordinator.
struct PublisherRecord {
  PublisherIdentity identity;
  AuthorityScope scope;
  bool live = false;
  /// Set once the boot has been fenced. A fenced boot may never publish again: a restarted
  /// publisher must present a fresh WorkerBootId.
  bool fenced = false;

  friend bool operator==(const PublisherRecord&, const PublisherRecord&) noexcept = default;
};

}  // namespace route_provenance
