// Route Provenance - persistence encoding, decoding and atomic replacement.
#include <cstdio>
#if defined(_WIN32)
#include <io.h>
#endif
#include <cstring>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "codec.hpp"
#include "route_provenance/persistence.hpp"
#include "route_provenance/version.hpp"
#include "store_internal.hpp"

namespace route_provenance {

using codec::is_known;
using codec::read_attempt;
using codec::read_authority;
using codec::read_bindings;
using codec::read_edge;
using codec::read_evidence;
using codec::read_node;
using codec::Reader;
using codec::write_attempt;
using codec::write_authority;
using codec::write_bindings;
using codec::write_edge;
using codec::write_evidence;
using codec::write_node;
using codec::Writer;

namespace {


constexpr char kMagic[8] = {'R', 'P', 'S', 'T', 'O', 'R', 'E', '1'};
constexpr std::uint32_t kHeaderSize = 128;
constexpr std::size_t kTrailerSize = Digest::kSize;
constexpr std::uint32_t kBindingPresencePath = 1U << 0U;
constexpr std::uint32_t kBindingPresencePlanner = 1U << 1U;
constexpr std::uint32_t kBindingPresenceEcmp = 1U << 2U;
constexpr std::uint32_t kBindingPresenceWeighted = 1U << 3U;
constexpr std::uint32_t kBindingPresenceAdaptation = 1U << 4U;
constexpr std::uint32_t kBindingPresenceConvergence = 1U << 5U;
constexpr std::uint32_t kBindingPresencePolicy = 1U << 6U;
constexpr std::uint32_t kBindingPresenceAll = kBindingPresencePath | kBindingPresencePlanner |
                                             kBindingPresenceEcmp | kBindingPresenceWeighted |
                                             kBindingPresenceAdaptation |
                                             kBindingPresenceConvergence | kBindingPresencePolicy;

[[nodiscard]] std::string sidecar_path(const std::string& path) {
  return path + ".tmp";
}

/// Builds a filesystem path from a UTF-8 string without relying on the deprecated u8path
/// overloads or on the process ANSI code page.
[[nodiscard]] std::filesystem::path to_path(const std::string& utf8) {
#if defined(_WIN32)
  const std::u8string wide(reinterpret_cast<const char8_t*>(utf8.data()), utf8.size());
  return std::filesystem::path(wide);
#else
  return std::filesystem::path(utf8);
#endif
}

}  // namespace

std::uint64_t StoreImage::node_count() const noexcept {
  std::uint64_t total = 0;
  for (const StoredLineage& lineage : lineages) {
    total += lineage.nodes.size();
  }
  return total;
}

std::uint64_t StoreImage::edge_count() const noexcept {
  std::uint64_t total = 0;
  for (const StoredLineage& lineage : lineages) {
    total += lineage.edges.size();
  }
  return total;
}

Status encode_store_image(const StoreImage& image, ByteVector& out, const Limits& limits) {
  if (image.lineages.size() > limits.max_lineages) {
    return Status::failure(Outcome::ResourceLimit, "image exceeds max_lineages");
  }
  if (image.node_count() > limits.max_persistence_nodes) {
    return Status::failure(Outcome::ResourceLimit, "image exceeds max_persistence_nodes");
  }
  if (image.edge_count() > limits.max_persistence_edges) {
    return Status::failure(Outcome::ResourceLimit, "image exceeds max_persistence_edges");
  }

  Writer body;
  for (const StoredLineage& lineage : image.lineages) {
    const std::size_t lineage_start = body.size();
    body.u64(lineage.state.id.value());
    body.u64(lineage.state.key.route.value());
    body.text(lineage.state.key.semantic_key);
    body.u16(static_cast<std::uint16_t>(lineage.state.lifecycle));
    body.u16(0);
    body.u64(lineage.state.current_route_generation.value());
    body.u64(lineage.state.current_node.value());
    body.u64(lineage.state.lineage_generation.value());
    body.u64(lineage.state.authority_generation.value());
    body.u64(lineage.state.last_publisher_boot.value());
    body.u32(static_cast<std::uint32_t>(lineage.nodes.size()));
    body.u32(static_cast<std::uint32_t>(lineage.edges.size()));
    body.u32(static_cast<std::uint32_t>(lineage.attempts.size()));
    body.u32(0);
    for (const ProvenanceNode& node : lineage.nodes) {
      write_node(body, node);
    }
    for (const ProvenanceEdge& edge : lineage.edges) {
      write_edge(body, edge);
    }
    for (const StoredAttempt& attempt : lineage.attempts) {
      write_attempt(body, attempt);
    }
    const std::size_t record_size = body.size() - lineage_start;
    if (record_size > limits.max_persistence_record_bytes) {
      return Status::failure(Outcome::ResourceLimit, "lineage record exceeds max_persistence_record_bytes");
    }
  }

  if (body.size() > limits.max_store_bytes) {
    return Status::failure(Outcome::ResourceLimit, "image exceeds max_store_bytes");
  }

  Writer writer;
  for (const char ch : kMagic) {
    writer.u8(static_cast<std::uint8_t>(ch));
  }
  writer.u32(kPersistenceFormatVersion);
  writer.u32(kHeaderSize);
  writer.u32(kGraphEncodingVersion);
  writer.u32(kDigestEncodingVersion);
  writer.u32(0);
  writer.u32(0);
  writer.u64(image.watermarks.store_generation.value());
  writer.u64(image.watermarks.epoch.value());
  writer.u64(image.watermarks.path_authority_generation.value());
  writer.u64(image.watermarks.policy_generation.value());
  writer.u64(image.watermarks.evidence_generation.value());
  writer.u64(image.watermarks.plan_generation.value());
  writer.u32(static_cast<std::uint32_t>(image.lineages.size()));
  writer.u32(static_cast<std::uint32_t>(image.node_count()));
  writer.u32(static_cast<std::uint32_t>(image.edge_count()));
  writer.u32(0);
  writer.u64(static_cast<std::uint64_t>(body.size()));
  while (writer.size() < kHeaderSize) {
    writer.u8(0);
  }

  ByteVector result = writer.data();
  result.insert(result.end(), body.data().begin(), body.data().end());
  const Digest trailer = Digest::hash(ByteSpan(result.data(), result.size()));
  for (std::size_t i = 0; i < kTrailerSize; ++i) {
    result.push_back(static_cast<std::byte>(trailer.data()[i]));
  }
  if (result.size() > limits.max_store_bytes) {
    return Status::failure(Outcome::ResourceLimit, "encoded image exceeds max_store_bytes");
  }
  out = std::move(result);
  return Status::ok();
}

Result<StoreImage> decode_store_image(ByteSpan bytes, const Limits& limits) {
  if (bytes.size() < kHeaderSize + kTrailerSize) {
    return Result<StoreImage>::failure(Outcome::StoreCorrupt, "store image is shorter than its header and trailer");
  }
  if (bytes.size() > limits.max_store_bytes) {
    return Result<StoreImage>::failure(Outcome::ResourceLimit, "store image exceeds max_store_bytes");
  }
  const auto* raw = reinterpret_cast<const std::uint8_t*>(bytes.data());
  for (std::size_t i = 0; i < 8; ++i) {
    if (raw[i] != static_cast<std::uint8_t>(kMagic[i])) {
      return Result<StoreImage>::failure(Outcome::StoreCorrupt, "bad store magic");
    }
  }
  Reader header(raw + 8, kHeaderSize - 8);
  const std::uint32_t format_version = header.u32();
  const std::uint32_t header_size = header.u32();
  const std::uint32_t graph_version = header.u32();
  const std::uint32_t digest_version = header.u32();
  const std::uint32_t flags = header.u32();
  static_cast<void>(header.u32());
  const std::uint64_t store_generation = header.u64();
  const std::uint64_t epoch = header.u64();
  const std::uint64_t path_generation = header.u64();
  const std::uint64_t policy_generation = header.u64();
  const std::uint64_t evidence_generation = header.u64();
  const std::uint64_t plan_generation = header.u64();
  const std::uint32_t lineage_count = header.u32();
  const std::uint32_t node_count = header.u32();
  const std::uint32_t edge_count = header.u32();
  static_cast<void>(header.u32());
  const std::uint64_t body_bytes = header.u64();
  if (header.failed() || header_size != kHeaderSize) {
    return Result<StoreImage>::failure(Outcome::StoreCorrupt, "malformed store header");
  }
  if (format_version != kPersistenceFormatVersion || graph_version != kGraphEncodingVersion ||
      digest_version != kDigestEncodingVersion) {
    return Result<StoreImage>::failure(Outcome::UnsupportedVersion,
                                       "unsupported store format or encoding version");
  }
  if (flags != 0) {
    return Result<StoreImage>::failure(Outcome::StoreCorrupt, "unsupported store flags");
  }
  const std::uint64_t expected_size =
      static_cast<std::uint64_t>(kHeaderSize) + body_bytes + kTrailerSize;
  if (expected_size != bytes.size()) {
    return Result<StoreImage>::failure(Outcome::StoreCorrupt, "store size does not match the header");
  }
  const Digest trailer = Digest::hash(ByteSpan(bytes.data(), bytes.size() - kTrailerSize));
  for (std::size_t i = 0; i < kTrailerSize; ++i) {
    if (trailer.data()[i] != raw[bytes.size() - kTrailerSize + i]) {
      return Result<StoreImage>::failure(Outcome::StoreCorrupt, "store integrity check failed");
    }
  }
  if (lineage_count > limits.max_lineages) {
    return Result<StoreImage>::failure(Outcome::StoreCorrupt, "lineage count exceeds the configured bound");
  }
  if (node_count > limits.max_persistence_nodes || edge_count > limits.max_persistence_edges) {
    return Result<StoreImage>::failure(Outcome::StoreCorrupt, "record counts exceed the configured bounds");
  }

  StoreImage image;
  image.watermarks.store_generation = ProvenanceGeneration::from_value(store_generation);
  image.watermarks.epoch = CoordinatorEpoch::from_value(epoch);
  image.watermarks.path_authority_generation = PathAuthorityGeneration::from_value(path_generation);
  image.watermarks.policy_generation = PolicyGeneration::from_value(policy_generation);
  image.watermarks.evidence_generation = EvidenceGeneration::from_value(evidence_generation);
  image.watermarks.plan_generation = ConvergencePlanGeneration::from_value(plan_generation);

  Reader reader(raw + kHeaderSize, static_cast<std::size_t>(body_bytes));
  std::uint64_t observed_nodes = 0;
  std::uint64_t observed_edges = 0;
  std::set<ProvenanceNodeId> global_nodes;
  std::set<ProvenanceEdgeId> global_edges;
  std::set<DerivationId> global_derivations;
  for (std::uint32_t i = 0; i < lineage_count; ++i) {
    const std::size_t lineage_start = reader.cursor();
    StoredLineage lineage;
    lineage.state.id = RouteLineageId::from_value(reader.u64());
    lineage.state.key.route = RouteId::from_value(reader.u64());
    lineage.state.key.semantic_key = reader.text(limits.max_semantic_key_bytes);
    const auto lifecycle_raw = reader.u16();
    static_cast<void>(reader.u16());
    lineage.state.current_route_generation = RouteGeneration::from_value(reader.u64());
    lineage.state.current_node = ProvenanceNodeId::from_value(reader.u64());
    lineage.state.lineage_generation = LineageGeneration::from_value(reader.u64());
    lineage.state.authority_generation = AuthorityGeneration::from_value(reader.u64());
    lineage.state.last_publisher_boot = WorkerBootId::from_value(reader.u64());
    const std::uint32_t nodes = reader.u32();
    const std::uint32_t edges = reader.u32();
    const std::uint32_t attempts = reader.u32();
    static_cast<void>(reader.u32());
    if (reader.failed()) {
      return Result<StoreImage>::failure(Outcome::StoreCorrupt, "truncated lineage header");
    }
    lineage.state.lifecycle = static_cast<LineageLifecycle>(lifecycle_raw);
    if (!is_known(lineage.state.lifecycle)) {
      return Result<StoreImage>::failure(Outcome::StoreCorrupt, "malformed lineage lifecycle");
    }
    if (!lineage.state.id.valid() || !lineage.state.key.route.valid() ||
        lineage.state.key.semantic_key.empty()) {
      return Result<StoreImage>::failure(Outcome::StoreCorrupt, "invalid lineage identity");
    }
    if (nodes > limits.max_nodes_per_lineage || edges > limits.max_edges_per_lineage ||
        attempts > limits.max_attempts_per_lineage) {
      return Result<StoreImage>::failure(Outcome::ResourceLimit, "lineage exceeds the configured bounds");
    }
    if (nodes > 0 && !lineage.state.lineage_generation.valid()) {
      return Result<StoreImage>::failure(Outcome::StoreCorrupt, "impossible lineage generation");
    }
    if (nodes == 0 && (lineage.state.current_node.valid() ||
                       lineage.state.current_route_generation.valid())) {
      return Result<StoreImage>::failure(Outcome::StoreCorrupt, "empty lineage claims current route state");
    }
    lineage.nodes.reserve(nodes);
    for (std::uint32_t n = 0; n < nodes; ++n) {
      ProvenanceNode node;
      if (!read_node(reader, node, limits)) {
        return Result<StoreImage>::failure(Outcome::StoreCorrupt, "malformed provenance record");
      }
      if (node.lineage != lineage.state.id) {
        return Result<StoreImage>::failure(Outcome::StoreCorrupt, "record lineage mismatch");
      }
      if (!node.id.valid()) {
        return Result<StoreImage>::failure(Outcome::StoreCorrupt, "invalid record identity");
      }
      if (!global_nodes.insert(node.id).second) {
        return Result<StoreImage>::failure(Outcome::StoreCorrupt, "duplicate provenance record");
      }
      const Status consistency = validate_node_consistency(node);
      if (!consistency.is_ok()) {
        return Result<StoreImage>::failure(Outcome::StoreCorrupt, consistency.detail());
      }
      if (node.kind != NodeKind::CompactedSummary && node.id != derive_node_id(node)) {
        return Result<StoreImage>::failure(Outcome::StoreCorrupt,
                                           "record identity does not match its content");
      }
      lineage.nodes.push_back(node);
    }
    lineage.edges.reserve(edges);
    for (std::uint32_t e = 0; e < edges; ++e) {
      ProvenanceEdge edge;
      if (!read_edge(reader, edge, limits)) {
        return Result<StoreImage>::failure(Outcome::StoreCorrupt, "malformed derivation edge");
      }
      if (edge.lineage != lineage.state.id) {
        return Result<StoreImage>::failure(Outcome::StoreCorrupt, "edge lineage mismatch");
      }
      if (!global_edges.insert(edge.id).second) {
        return Result<StoreImage>::failure(Outcome::StoreCorrupt, "duplicate derivation edge");
      }
      if (!global_derivations.insert(edge.derivation).second) {
        return Result<StoreImage>::failure(Outcome::StoreCorrupt, "duplicate derivation identity");
      }
      const Status consistency = validate_edge_consistency(edge);
      if (!consistency.is_ok()) {
        return Result<StoreImage>::failure(Outcome::StoreCorrupt, consistency.detail());
      }
      if (edge.derivation != compute_derivation_id(edge) || edge.id != compute_edge_id(edge)) {
        return Result<StoreImage>::failure(Outcome::StoreCorrupt,
                                           "edge identity does not match its content");
      }
      lineage.edges.push_back(edge);
    }
    lineage.attempts.reserve(attempts);
    for (std::uint32_t a = 0; a < attempts; ++a) {
      StoredAttempt attempt;
      if (!read_attempt(reader, attempt, limits)) {
        return Result<StoreImage>::failure(Outcome::StoreCorrupt, "malformed attempt record");
      }
      if (!attempt.publisher.valid() || !attempt.attempt.valid() || !attempt.node.valid()) {
        return Result<StoreImage>::failure(Outcome::StoreCorrupt, "invalid attempt identity");
      }
      lineage.attempts.push_back(attempt);
    }
    const std::size_t record_size = reader.cursor() - lineage_start;
    if (record_size > limits.max_persistence_record_bytes) {
      return Result<StoreImage>::failure(Outcome::ResourceLimit,
                                         "lineage record exceeds max_persistence_record_bytes");
    }
    observed_nodes += lineage.nodes.size();
    observed_edges += lineage.edges.size();
    image.lineages.push_back(std::move(lineage));
  }
  if (reader.failed()) {
    return Result<StoreImage>::failure(Outcome::StoreCorrupt, "truncated store body");
  }
  if (!reader.at_end()) {
    return Result<StoreImage>::failure(Outcome::StoreCorrupt, "trailing bytes after the store body");
  }
  if (observed_nodes != node_count || observed_edges != edge_count) {
    return Result<StoreImage>::failure(Outcome::StoreCorrupt, "store record counts disagree");
  }

  // Structural validation: every edge references an existing record of its own lineage and the
  // graph is acyclic. This is an independent check, not a reuse of the writer's assumptions.
  for (const StoredLineage& lineage : image.lineages) {
    ProvenanceGraph graph;
    for (const ProvenanceNode& node : lineage.nodes) {
      const Status added = graph.add_node(node, limits);
      if (!added.is_ok()) {
        return Result<StoreImage>::failure(Outcome::StoreCorrupt, added.detail());
      }
    }
    for (const ProvenanceEdge& edge : lineage.edges) {
      const Status added = graph.add_edge(edge, limits);
      if (!added.is_ok()) {
        return Result<StoreImage>::failure(Outcome::StoreCorrupt, added.detail());
      }
    }
    const Status structure = graph.validate_structure();
    if (!structure.is_ok()) {
      return Result<StoreImage>::failure(Outcome::StoreCorrupt, structure.detail());
    }
  }
  return Result<StoreImage>::ok(std::move(image));
}

Result<StoreImage> read_store_image(const std::string& path, const Limits& limits) {
  std::error_code error;
  const std::uintmax_t size = std::filesystem::file_size(to_path(path), error);
  if (error) {
    return Result<StoreImage>::failure(Outcome::IoFailure, "cannot determine store file size");
  }
  if (size > limits.max_store_bytes) {
    return Result<StoreImage>::failure(Outcome::ResourceLimit, "store file exceeds max_store_bytes");
  }
  std::FILE* file = nullptr;
  const std::filesystem::path native = to_path(path);
#if defined(_WIN32)
  if (_wfopen_s(&file, native.wstring().c_str(), L"rb") != 0) {
    file = nullptr;
  }
#else
  file = std::fopen(native.string().c_str(), "rb");
#endif
  if (file == nullptr) {
    return Result<StoreImage>::failure(Outcome::IoFailure, "cannot open store file for reading");
  }
  ByteVector bytes(static_cast<std::size_t>(size));
  const std::size_t read = bytes.empty() ? 0 : std::fread(bytes.data(), 1, bytes.size(), file);
  std::fclose(file);
  if (read != bytes.size()) {
    return Result<StoreImage>::failure(Outcome::IoFailure, "short read of store file");
  }
  return decode_store_image(ByteSpan(bytes.data(), bytes.size()), limits);
}

Status write_store_image_atomic(const StoreImage& image, const std::string& path, const Limits& limits) {
  ByteVector bytes;
  const Status encoded = encode_store_image(image, bytes, limits);
  if (!encoded.is_ok()) {
    return encoded;
  }
  const std::string temporary = sidecar_path(path);
  const std::filesystem::path temporary_path = to_path(temporary);
  std::FILE* file = nullptr;
#if defined(_WIN32)
  if (_wfopen_s(&file, temporary_path.wstring().c_str(), L"wb") != 0) {
    file = nullptr;
  }
#else
  file = std::fopen(temporary_path.string().c_str(), "wb");
#endif
  if (file == nullptr) {
    return Status::failure(Outcome::IoFailure, "cannot open the temporary store file for writing");
  }
  const std::size_t written = std::fwrite(bytes.data(), 1, bytes.size(), file);
  if (written != bytes.size()) {
    std::fclose(file);
    std::error_code ignored;
    static_cast<void>(std::filesystem::remove(temporary_path, ignored));
    return Status::failure(Outcome::IoFailure, "short write of the temporary store file");
  }
  if (std::fflush(file) != 0) {
    std::fclose(file);
    std::error_code ignored;
    static_cast<void>(std::filesystem::remove(temporary_path, ignored));
    return Status::failure(Outcome::IoFailure, "cannot flush the temporary store file");
  }
#if defined(_WIN32)
  if (_commit(_fileno(file)) != 0) {
    std::fclose(file);
    std::error_code ignored;
    static_cast<void>(std::filesystem::remove(temporary_path, ignored));
    return Status::failure(Outcome::IoFailure, "cannot flush the temporary store file to disk");
  }
#endif
  if (std::fclose(file) != 0) {
    std::error_code ignored;
    static_cast<void>(std::filesystem::remove(temporary_path, ignored));
    return Status::failure(Outcome::IoFailure, "cannot close the temporary store file");
  }
  std::error_code error;
  const std::filesystem::path destination = to_path(path);
  std::filesystem::rename(temporary_path, destination, error);
  if (error) {
    std::error_code ignored;
    static_cast<void>(std::filesystem::remove(temporary_path, ignored));
    return Status::failure(Outcome::IoFailure, "cannot replace the store file atomically");
  }
  return Status::ok();
}

// ---------------------------------------------------------------------------
// Store-level persistence
// ---------------------------------------------------------------------------

Result<StoreImage> ProvenanceStore::export_image() const {
  StoreImage image;
  std::vector<std::shared_ptr<Lineage>> lineages;
  std::vector<std::shared_lock<std::shared_mutex>> locks;
  {
    std::shared_lock<std::shared_mutex> registry_lock(impl_->registry_mutex);
    lineages.reserve(impl_->lineages.size());
    for (const auto& entry : impl_->lineages) {
      lineages.push_back(entry.second);
    }
    locks.reserve(lineages.size());
    for (const std::shared_ptr<Lineage>& lineage : lineages) {
      locks.emplace_back(lineage->mutex);
    }
    image.watermarks = impl_->read_watermarks();
    for (const std::shared_ptr<Lineage>& lineage : lineages) {
      StoredLineage stored;
      stored.state = lineage->state;
      stored.nodes = lineage->graph.nodes_in_order();
      stored.edges = lineage->graph.edges_in_order();
      stored.attempts.reserve(lineage->attempts.size());
      for (const auto& entry : lineage->attempts) {
        StoredAttempt attempt;
        attempt.publisher = entry.first.publisher;
        attempt.attempt = entry.first.attempt;
        attempt.request = entry.second.request;
        attempt.node = entry.second.node;
        attempt.edges = entry.second.edges;
        attempt.outcome = entry.second.outcome;
        attempt.lifecycle = entry.second.lifecycle;
        attempt.currentness = entry.second.currentness;
        stored.attempts.push_back(std::move(attempt));
      }
      image.lineages.push_back(std::move(stored));
    }
  }
  return Result<StoreImage>::ok(std::move(image));
}

Status ProvenanceStore::save(const std::string& path) const {
  if (path.empty()) {
    return Status::failure(Outcome::MalformedRequest, "store path is required");
  }
  Result<StoreImage> image = export_image();
  if (!image.has_value()) {
    return Status::failure(image.outcome(), image.detail());
  }
  return write_store_image_atomic(image.value(), path, impl_->limits);
}

Status ProvenanceStore::load(const std::string& path) {
  if (path.empty()) {
    return Status::failure(Outcome::MalformedRequest, "store path is required");
  }
  Result<StoreImage> decoded = read_store_image(path, impl_->limits);
  if (!decoded.has_value()) {
    return Status::failure(decoded.outcome(), decoded.detail());
  }
  StoreImage& image = decoded.value();

  std::map<RouteLineageId, std::shared_ptr<Lineage>> lineages;
  std::map<RouteId, RouteLineageId> route_index;
  for (StoredLineage& stored : image.lineages) {
    auto lineage = std::make_shared<Lineage>();
    lineage->state = stored.state;
    lineage->state.history_node_count = 0;
    lineage->state.compacted_node_count = 0;
    for (const ProvenanceNode& node : stored.nodes) {
      const Status added = lineage->graph.add_node(node, impl_->limits);
      if (!added.is_ok()) {
        return Status::failure(Outcome::StoreCorrupt,
                               std::string("stored record rejected: ") + added.detail());
      }
    }
    for (const ProvenanceEdge& edge : stored.edges) {
      const Status added = lineage->graph.add_edge(edge, impl_->limits);
      if (!added.is_ok()) {
        return Status::failure(Outcome::StoreCorrupt,
                               std::string("stored derivation rejected: ") + added.detail());
      }
    }
    const Status structure = lineage->graph.validate_structure();
    if (!structure.is_ok()) {
      return Status::failure(Outcome::StoreCorrupt,
                             std::string("stored lineage is inconsistent: ") + structure.detail());
    }
    for (const StoredAttempt& attempt : stored.attempts) {
      AttemptRecord record;
      record.request = attempt.request;
      record.node = attempt.node;
      record.edges = attempt.edges;
      record.outcome = attempt.outcome;
      record.lifecycle = attempt.lifecycle;
      record.currentness = attempt.currentness;
      lineage->attempts.emplace(AttemptKey{attempt.publisher, attempt.attempt}, std::move(record));
    }
    // Conservative recovery: a record that was current only because a live session vouched for
    // it is not current after a restart. Its history is untouched.
    const std::vector<ProvenanceNode> nodes = lineage->graph.nodes_in_order();
    for (const ProvenanceNode& node : nodes) {
      if (node.currentness == Currentness::Current && node.lifecycle == NodeLifecycle::Current) {
        const Status demoted = lineage->graph.update_node_state(
            node.id, NodeLifecycle::RevalidationRequired, Currentness::RevalidationRequired, true);
        if (!demoted.is_ok()) {
          return Status::failure(Outcome::StoreCorrupt,
                                 std::string("recovery could not demote a record: ") + demoted.detail());
        }
      }
    }
    for (const ProvenanceNode& node : lineage->graph.nodes_in_order()) {
      if (node_is_history_record(node)) {
        lineage->state.history_node_count += 1;
      }
      if (node.kind == NodeKind::CompactedSummary) {
        lineage->state.compacted_node_count += 1;
      }
    }
    lineage->state.node_count = lineage->graph.node_count();
    lineage->state.edge_count = lineage->graph.edge_count();
    if (lineage->state.current_node.valid() &&
        lineage->graph.find_node(lineage->state.current_node) == nullptr) {
      return Status::failure(Outcome::StoreCorrupt, "stored lineage current record is missing");
    }
    if (lineages.find(stored.state.id) != lineages.end()) {
      return Status::failure(Outcome::StoreCorrupt, "duplicate lineage identity");
    }
    if (route_index.find(stored.state.key.route) != route_index.end()) {
      return Status::failure(Outcome::StoreCorrupt, "duplicate route identity");
    }
    route_index.emplace(stored.state.key.route, stored.state.id);
    lineages.emplace(stored.state.id, std::move(lineage));
  }

  {
    std::unique_lock<std::shared_mutex> registry_lock(impl_->registry_mutex);
    std::unique_lock<std::shared_mutex> index_lock(impl_->index_mutex);
    impl_->lineages = std::move(lineages);
    impl_->route_index = std::move(route_index);
    impl_->node_owner.clear();
    impl_->route_generation_index.clear();
    impl_->path_index.clear();
    impl_->path_authority_index.clear();
    impl_->policy_index.clear();
    impl_->evidence_index.clear();
    impl_->boot_index.clear();
    impl_->publisher_index.clear();
    impl_->watermarks = image.watermarks;
    for (const auto& entry : impl_->lineages) {
      for (const ProvenanceNode& node : entry.second->graph.nodes_in_order()) {
        impl_->node_owner[node.id] = entry.first;
        if (node.kind == NodeKind::RouteGeneration) {
          impl_->route_generation_index[node.route][node.route_generation] = node.id;
        }
        if (node.bindings.path.has_value()) {
          impl_->path_index[node.bindings.path->path].insert(node.id);
          impl_->path_authority_index[node.bindings.path->generation].insert(node.id);
        }
        if (node.bindings.planner.has_value()) {
          impl_->path_index[node.bindings.planner->selected_path].insert(node.id);
        }
        if (node.bindings.policy.has_value()) {
          impl_->policy_index[node.bindings.policy->generation].insert(node.id);
        }
        if (node.bindings.adaptation.has_value()) {
          impl_->policy_index[node.bindings.adaptation->policy].insert(node.id);
          impl_->evidence_index[node.bindings.adaptation->evidence].insert(node.id);
        }
        impl_->boot_index[node.authority.publisher.boot].insert(node.id);
        impl_->publisher_index[node.authority.publisher.publisher].insert(node.id);
      }
    }
  }
  {
    // Live session authority is never restored by a load.
    std::lock_guard<std::mutex> lock(impl_->publisher_mutex);
    impl_->publishers.clear();
  }
  impl_->recovered = true;

  std::vector<std::shared_ptr<Lineage>> lineages_snapshot;
  {
    std::shared_lock<std::shared_mutex> registry_lock(impl_->registry_mutex);
    for (const auto& entry : impl_->lineages) {
      lineages_snapshot.push_back(entry.second);
    }
  }
  for (const std::shared_ptr<Lineage>& lineage : lineages_snapshot) {
    std::unique_lock<std::shared_mutex> lock(lineage->mutex);
    impl_->reevaluate_all(*lineage);
  }
  return Status::ok(Outcome::Updated, "store loaded and recovered");
}

}  // namespace route_provenance