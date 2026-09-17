// Route Provenance - versioned, integrity-checked persistence.
//
// The persisted format is deterministic, bounded and integrity-checked. It carries lineage
// identity, records, typed derivations, generations, reasons, upstream bindings, authority
// provenance, corrections, bounded history and digests. Live session authority is never
// persisted as current: after a restart every record that depended on live process state
// requires revalidation.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "route_provenance/digest.hpp"
#include "route_provenance/enums.hpp"
#include "route_provenance/limits.hpp"
#include "route_provenance/lineage.hpp"
#include "route_provenance/node.hpp"
#include "route_provenance/result.hpp"
#include "route_provenance/store.hpp"

namespace route_provenance {

/// Publication-attempt ledger entry as stored.
struct StoredAttempt {
  PublisherId publisher;
  MutationAttemptId attempt;
  Digest request;
  ProvenanceNodeId node;
  std::vector<ProvenanceEdgeId> edges;
  Outcome outcome = Outcome::Created;
  NodeLifecycle lifecycle = NodeLifecycle::Current;
  Currentness currentness = Currentness::HistoricalOnly;
};

/// One lineage as stored.
struct StoredLineage {
  LineageState state;
  std::vector<ProvenanceNode> nodes;
  std::vector<ProvenanceEdge> edges;
  std::vector<StoredAttempt> attempts;
};

/// Structured image of a persisted store. Encode and decode are symmetric and both perform
/// full structural validation, so an image can be constructed, inspected or attacked without
/// depending on store internals.
struct StoreImage {
  DependencyWatermarks watermarks;
  std::vector<StoredLineage> lineages;

  [[nodiscard]] std::uint64_t node_count() const noexcept;
  [[nodiscard]] std::uint64_t edge_count() const noexcept;
};

/// Serialises an image. Rejects images whose record or total size exceeds the configured
/// bounds. The encoding is deterministic and versioned.
[[nodiscard]] Status encode_store_image(const StoreImage& image, ByteVector& out, const Limits& limits);

/// Decodes an image. Rejects: wrong magic, unsupported version, truncated input, trailing
/// bytes, integrity mismatch, absurd counts, duplicate records, duplicate edges, missing
/// endpoints, cycles, invalid source generations, impossible lifecycles and malformed enums.
[[nodiscard]] Result<StoreImage> decode_store_image(ByteSpan bytes, const Limits& limits);

/// Reads a store file. The whole file must decode exactly.
[[nodiscard]] Result<StoreImage> read_store_image(const std::string& path, const Limits& limits);

/// Writes a store file atomically: the image is written to a temporary file in the same
/// directory, flushed to stable storage, and then renamed over the destination.
[[nodiscard]] Status write_store_image_atomic(const StoreImage& image, const std::string& path,
                                              const Limits& limits);

}  // namespace route_provenance
