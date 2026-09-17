// Route Provenance - resource limits.
//
// Every field in this structure is consulted by the runtime and is covered by a test that
// shrinks the limit and asserts the corresponding structured rejection. There are no
// decorative limits.
#pragma once

#include <cstdint>
#include <string>

namespace route_provenance {

struct Limits {
  /// Store-level bounds.
  std::uint32_t max_lineages = 100'000;
  std::uint64_t max_store_bytes = 512ULL * 1024ULL * 1024ULL;

  /// Per-lineage graph bounds.
  std::uint32_t max_nodes_per_lineage = 4'096;
  std::uint32_t max_edges_per_lineage = 16'384;
  std::uint32_t max_history_nodes_per_lineage = 2'048;
  std::uint32_t max_attempts_per_lineage = 4'096;
  std::uint32_t max_parents_per_node = 64;
  std::uint32_t max_children_per_node = 64;

  /// Traversal and query bounds.
  std::uint32_t max_traversal_depth = 64;
  std::uint32_t max_query_results = 4'096;
  std::uint32_t max_visited_nodes = 16'384;
  std::uint32_t max_explanation_nodes = 128;

  /// Publication bounds.
  std::uint32_t max_batch_size = 256;
  std::uint32_t max_evidence_entries = 32;
  std::uint32_t max_semantic_key_bytes = 128;

  /// Distributed bounds.
  std::uint32_t max_frame_bytes = 256 * 1024;
  std::uint32_t max_publishers = 64;
  std::uint32_t max_sessions = 64;
  /// Maximum time a peer may take to complete a single frame before the session is failed.
  /// This is product behaviour, not a test timeout: a partial-frame peer is disconnected.
  std::uint32_t max_frame_assembly_ms = 10'000;

  /// Persistence bounds.
  std::uint32_t max_persistence_record_bytes = 1024 * 1024;
  std::uint32_t max_persistence_nodes = 200'000;
  std::uint32_t max_persistence_edges = 800'000;

  [[nodiscard]] static Limits defaults() noexcept { return Limits{}; }

  /// Structural self-check: detects inconsistent limits (for example a per-node parent bound
  /// larger than the per-lineage edge bound). Returns false and fills \p error on failure.
  [[nodiscard]] bool validate(std::string& error) const;
};

}  // namespace route_provenance
