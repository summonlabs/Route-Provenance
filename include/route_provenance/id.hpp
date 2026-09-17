// Route Provenance - strongly typed identities.
//
// Every identity in this runtime is a distinct C++ type. There is no implicit conversion
// between identities, and no identity is interchangeable with a plain integer. The zero
// value is never a valid identity or generation; it is the "absent" sentinel.
#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace route_provenance {

enum class IdClass : std::uint8_t {
  Identifier = 0,  ///< Valid values are >= 1.
  Generation = 1,  ///< Valid values are >= 1; monotonic and non-wrapping.
};

/// Strongly typed 64-bit identity. Tag selects a distinct type, Kind selects validity rules.
template <class Tag, IdClass Kind = IdClass::Identifier>
class StrongId {
 public:
  using value_type = std::uint64_t;
  static constexpr IdClass id_class = Kind;

  constexpr StrongId() noexcept = default;
  explicit constexpr StrongId(std::uint64_t raw) noexcept : raw_(raw) {}

  [[nodiscard]] static constexpr StrongId from_value(std::uint64_t raw) noexcept {
    return StrongId(raw);
  }

  [[nodiscard]] constexpr std::uint64_t value() const noexcept { return raw_; }
  [[nodiscard]] constexpr bool valid() const noexcept { return raw_ != 0; }
  [[nodiscard]] constexpr explicit operator bool() const noexcept { return raw_ != 0; }

  /// Checked successor. Returns nullopt instead of wrapping at the 64-bit boundary so that
  /// "generations never wrap" is enforced by construction rather than by convention.
  [[nodiscard]] constexpr std::optional<StrongId> try_next() const noexcept {
    if (raw_ == kMax) {
      return std::nullopt;
    }
    return StrongId(raw_ + 1);
  }

  [[nodiscard]] std::string to_string() const { return std::to_string(raw_); }

  /// Parses a canonical base-10 representation. Rejects empty input, sign characters,
  /// surrounding whitespace, non-digits, overflow and the invalid zero value.
  [[nodiscard]] static std::optional<StrongId> parse(std::string_view text) noexcept {
    if (text.empty() || text.size() > 20) {
      return std::nullopt;
    }
    std::uint64_t value = 0;
    for (const char ch : text) {
      if (ch < '0' || ch > '9') {
        return std::nullopt;
      }
      const std::uint64_t digit = static_cast<std::uint64_t>(ch - '0');
      if (value > (kMax - digit) / 10U) {
        return std::nullopt;
      }
      value = value * 10U + digit;
    }
    if (value == 0) {
      return std::nullopt;
    }
    return StrongId(value);
  }

  friend constexpr bool operator==(StrongId, StrongId) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(StrongId, StrongId) noexcept = default;

 private:
  static constexpr std::uint64_t kMax = 0xFFFF'FFFF'FFFF'FFFFULL;
  std::uint64_t raw_ = 0;
};

#define RP_DECLARE_ID(name, kind)   \
  struct name##Tag;                 \
  using name = StrongId<name##Tag, kind>

// Route Provenance owned identities.
RP_DECLARE_ID(RouteProvenanceId, IdClass::Identifier);
RP_DECLARE_ID(ProvenanceNodeId, IdClass::Identifier);
RP_DECLARE_ID(ProvenanceEdgeId, IdClass::Identifier);
RP_DECLARE_ID(RouteLineageId, IdClass::Identifier);
RP_DECLARE_ID(DerivationId, IdClass::Identifier);
RP_DECLARE_ID(SnapshotId, IdClass::Identifier);
RP_DECLARE_ID(RoutingNamespaceId, IdClass::Identifier);

// Generations owned by Route Provenance.
RP_DECLARE_ID(ProvenanceGeneration, IdClass::Generation);
RP_DECLARE_ID(LineageGeneration, IdClass::Generation);
RP_DECLARE_ID(AuthorityGeneration, IdClass::Generation);

// Identities and generations owned by neighbouring Fabric OS authorities. Route Provenance
// only ever binds these; it never mints or validates them on the owner's behalf.
RP_DECLARE_ID(RouteId, IdClass::Identifier);
RP_DECLARE_ID(RouteGeneration, IdClass::Generation);
RP_DECLARE_ID(PathId, IdClass::Identifier);
RP_DECLARE_ID(PathAuthorityGeneration, IdClass::Generation);
RP_DECLARE_ID(PlannerRequestId, IdClass::Identifier);
RP_DECLARE_ID(PlannerGeneration, IdClass::Generation);
RP_DECLARE_ID(AdaptationDecisionId, IdClass::Identifier);
RP_DECLARE_ID(AdaptationGeneration, IdClass::Generation);
RP_DECLARE_ID(ConvergencePlanId, IdClass::Identifier);
RP_DECLARE_ID(ConvergencePlanGeneration, IdClass::Generation);
RP_DECLARE_ID(ConvergenceStepId, IdClass::Identifier);
RP_DECLARE_ID(EcmpGroupId, IdClass::Identifier);
RP_DECLARE_ID(MembershipGeneration, IdClass::Generation);
RP_DECLARE_ID(AssignmentGeneration, IdClass::Generation);
RP_DECLARE_ID(WeightedPathSetId, IdClass::Identifier);
RP_DECLARE_ID(WeightPolicyGeneration, IdClass::Generation);
RP_DECLARE_ID(PolicyGeneration, IdClass::Generation);
RP_DECLARE_ID(EvidenceGeneration, IdClass::Generation);
RP_DECLARE_ID(FabricEpoch, IdClass::Generation);
RP_DECLARE_ID(TopologyGeneration, IdClass::Generation);
RP_DECLARE_ID(LinkStateGeneration, IdClass::Generation);
RP_DECLARE_ID(PortGeneration, IdClass::Generation);
RP_DECLARE_ID(CapabilityGeneration, IdClass::Generation);
RP_DECLARE_ID(FailureDomainGeneration, IdClass::Generation);

// Distributed publication identities.
RP_DECLARE_ID(PublisherId, IdClass::Identifier);
RP_DECLARE_ID(WorkerBootId, IdClass::Identifier);
RP_DECLARE_ID(CoordinatorEpoch, IdClass::Generation);
RP_DECLARE_ID(MutationAttemptId, IdClass::Identifier);

#undef RP_DECLARE_ID

/// Heterogeneous hasher usable with any StrongId specialisation.
struct StrongIdHash {
  template <class Id>
  [[nodiscard]] std::size_t operator()(const Id& id) const noexcept {
    return static_cast<std::size_t>(id.value() * 0x9E37'79B9'7F4A'7C15ULL);
  }
};

}  // namespace route_provenance
