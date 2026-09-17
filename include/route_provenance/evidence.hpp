// Route Provenance - canonical evidence vectors.
//
// An evidence vector binds the exact upstream generations a derivation depends on. Entries
// are canonicalised (sorted by field id, de-duplicated) so that equivalent evidence
// inserted in a different order yields an identical digest, explanation and snapshot.
#pragma once

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "route_provenance/digest.hpp"
#include "route_provenance/limits.hpp"
#include "route_provenance/result.hpp"

namespace route_provenance {

enum class EvidenceField : std::uint16_t {
  TopologyGeneration = 1,
  LinkStateGeneration = 2,
  PortGeneration = 3,
  CapabilityGeneration = 4,
  FailureDomainGeneration = 5,
  FabricEpoch = 6,
  PathAuthorityGeneration = 7,
  PlannerGeneration = 8,
  AdaptivePolicyGeneration = 9,
  ConvergencePlanGeneration = 10,
  RouteGeneration = 11,
  PublisherGeneration = 12,
};

[[nodiscard]] std::string_view to_string(EvidenceField field) noexcept;
[[nodiscard]] std::optional<EvidenceField> parse_evidence_field(std::string_view text) noexcept;

struct EvidenceEntry {
  EvidenceField field = EvidenceField::TopologyGeneration;
  std::uint64_t value = 0;

  friend bool operator==(const EvidenceEntry&, const EvidenceEntry&) noexcept = default;
};

class EvidenceVector {
 public:
  EvidenceVector() = default;

  /// Canonicalises the supplied entries. Rejects zero values (an absent generation is not the
  /// same as generation zero) and conflicting duplicates for the same field.
  [[nodiscard]] static Result<EvidenceVector> create(std::vector<EvidenceEntry> entries,
                                                     const Limits& limits);

  [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }
  [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
  [[nodiscard]] const std::vector<EvidenceEntry>& entries() const noexcept { return entries_; }

  [[nodiscard]] bool contains(EvidenceField field) const noexcept;
  [[nodiscard]] std::optional<std::uint64_t> get(EvidenceField field) const noexcept;

  /// Structural equality over canonicalised content.
  friend bool operator==(const EvidenceVector&, const EvidenceVector&) noexcept = default;

  [[nodiscard]] Digest digest() const noexcept;
  void encode(CanonicalEncoder& encoder, std::uint16_t field) const;

 private:
  std::vector<EvidenceEntry> entries_;
};

}  // namespace route_provenance
