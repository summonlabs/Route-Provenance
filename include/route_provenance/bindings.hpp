// Route Provenance - upstream bindings.
//
// Route Provenance references authoritative objects by exact identity and generation. It
// never copies authoritative content, and it never re-derives the referenced authority.
#pragma once

#include <cstdint>
#include <optional>

#include "route_provenance/digest.hpp"
#include "route_provenance/enums.hpp"
#include "route_provenance/id.hpp"
#include "route_provenance/result.hpp"

namespace route_provenance {

/// Path Authority binding: exact path, exact authorization generation, decision digest.
struct PathBinding {
  PathId path;
  PathAuthorityGeneration generation;
  Digest decision_digest;

  friend bool operator==(const PathBinding&, const PathBinding&) noexcept = default;
};

/// Path Planner binding: the planner never has its selection history inferred later.
struct PlannerBinding {
  PlannerRequestId request;
  PlannerGeneration generation;
  std::uint32_t candidate_rank = 0;
  Digest plan_digest;
  PathId selected_path;

  friend bool operator==(const PlannerBinding&, const PlannerBinding&) noexcept = default;
};

/// ECMP binding: authoritative object generations only, no bucket maps.
struct EcmpBinding {
  EcmpGroupId group;
  MembershipGeneration membership;
  AssignmentGeneration assignment;

  friend bool operator==(const EcmpBinding&, const EcmpBinding&) noexcept = default;
};

/// Weighted Path Fabric binding.
struct WeightedPathBinding {
  WeightedPathSetId set;
  WeightPolicyGeneration policy;
  AssignmentGeneration assignment;

  friend bool operator==(const WeightedPathBinding&, const WeightedPathBinding&) noexcept = default;
};

/// Adaptive Routing Fabric binding.
struct AdaptationBinding {
  AdaptationDecisionId decision;
  AdaptationGeneration generation;
  PolicyGeneration policy;
  EvidenceGeneration evidence;
  Digest decision_digest;

  friend bool operator==(const AdaptationBinding&, const AdaptationBinding&) noexcept = default;
};

/// Route Convergence binding.
struct ConvergenceBinding {
  ConvergencePlanId plan;
  ConvergencePlanGeneration generation;
  ConvergenceStepId step;
  Digest completion_evidence;

  friend bool operator==(const ConvergenceBinding&, const ConvergenceBinding&) noexcept = default;
};

/// Policy binding. A policy name is never sufficient; the exact generation is required.
struct PolicyBinding {
  PolicyGeneration generation;

  friend bool operator==(const PolicyBinding&, const PolicyBinding&) noexcept = default;
};

struct Bindings {
  std::optional<PathBinding> path;
  std::optional<PlannerBinding> planner;
  std::optional<EcmpBinding> ecmp;
  std::optional<WeightedPathBinding> weighted;
  std::optional<AdaptationBinding> adaptation;
  std::optional<ConvergenceBinding> convergence;
  std::optional<PolicyBinding> policy;

  [[nodiscard]] bool empty() const noexcept;

  friend bool operator==(const Bindings&, const Bindings&) noexcept = default;
};

/// Checks that every binding present is well formed, and that the bindings required by the
/// reason code are present. Returns MalformedRequest / InvalidSourceGeneration on failure.
[[nodiscard]] Status validate_bindings(ReasonCode reason, const Bindings& bindings);

void encode_bindings(const Bindings& bindings, CanonicalEncoder& encoder, std::uint16_t field);

}  // namespace route_provenance
