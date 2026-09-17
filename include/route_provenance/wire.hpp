// Route Provenance - framed wire protocol.
//
// Frames are fixed-layout, explicitly versioned, bounded in size and integrity-checked over
// the semantic header and the payload. Raw C++ layouts are never serialised. Every payload is
// a canonical field bag: unknown field identifiers, duplicated fields, length mismatches,
// trailing bytes, unknown message identifiers and unknown enumeration values are rejected.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "route_provenance/authority.hpp"
#include "route_provenance/digest.hpp"
#include "route_provenance/explanation.hpp"
#include "route_provenance/limits.hpp"
#include "route_provenance/lineage.hpp"
#include "route_provenance/node.hpp"
#include "route_provenance/persistence.hpp"
#include "route_provenance/store.hpp"
#include "route_provenance/version.hpp"

namespace route_provenance {

/// Size of the fixed frame header on the wire.
inline constexpr std::size_t kFrameHeaderBytes = 64;
/// Size of the integrity trailer on the wire.
inline constexpr std::size_t kFrameTrailerBytes = Digest::kSize;

/// Semantic frame header. Every field participates in the frame integrity digest.
struct FrameHeader {
  std::uint16_t protocol_version = kWireProtocolVersion;
  MessageId message = MessageId::Hello;
  std::uint16_t flags = 0;
  CoordinatorEpoch epoch;
  PublisherId publisher;
  WorkerBootId boot;
  MutationAttemptId attempt;
  std::uint32_t payload_bytes = 0;
};

struct DecodedFrame {
  FrameHeader header;
  ByteVector payload;
};

/// Digest over the canonical encoding of the semantic header and the payload bytes.
[[nodiscard]] Digest frame_digest(const FrameHeader& header, ByteSpan payload) noexcept;

/// Encodes one complete frame. Rejects payloads larger than the configured frame bound.
[[nodiscard]] Status encode_frame(const FrameHeader& header, ByteSpan payload, const Limits& limits,
                                  ByteVector& out);

/// Decodes exactly one complete frame. Rejects short input, bad magic, unsupported protocol
/// version, unknown message identifier, non-zero reserved fields, oversized payloads, integrity
/// mismatch and trailing bytes.
[[nodiscard]] Result<DecodedFrame> decode_frame(ByteSpan frame, const Limits& limits);

/// Canonical field bag used as the payload of every message.
class FieldBag {
 public:
  FieldBag() = default;

  /// Parses a canonical encoding. Rejects duplicates, length mismatches and trailing bytes.
  [[nodiscard]] static Result<FieldBag> decode(ByteSpan encoded, const Limits& limits);

  void set_bool(std::uint16_t field, bool value);
  void set_u8(std::uint16_t field, std::uint8_t value);
  void set_u16(std::uint16_t field, std::uint16_t value);
  void set_u32(std::uint16_t field, std::uint32_t value);
  void set_u64(std::uint16_t field, std::uint64_t value);
  void set_text(std::uint16_t field, std::string_view value);
  void set_digest(std::uint16_t field, const Digest& value);
  void set_bytes(std::uint16_t field, ByteSpan value);
  void set_nested(std::uint16_t field, const FieldBag& nested);

  [[nodiscard]] bool has(std::uint16_t field) const noexcept;
  [[nodiscard]] std::optional<bool> boolean(std::uint16_t field) const noexcept;
  [[nodiscard]] std::optional<std::uint8_t> u8(std::uint16_t field) const noexcept;
  [[nodiscard]] std::optional<std::uint16_t> u16(std::uint16_t field) const noexcept;
  [[nodiscard]] std::optional<std::uint32_t> u32(std::uint16_t field) const noexcept;
  [[nodiscard]] std::optional<std::uint64_t> u64(std::uint16_t field) const noexcept;
  [[nodiscard]] std::optional<std::string> text(std::uint16_t field) const;
  [[nodiscard]] std::optional<Digest> digest(std::uint16_t field) const;
  [[nodiscard]] std::optional<ByteVector> bytes(std::uint16_t field) const;
  [[nodiscard]] std::optional<FieldBag> nested(std::uint16_t field, const Limits& limits) const;

  /// Field identifiers present, in ascending order. Used to reject unknown fields.
  [[nodiscard]] std::vector<std::uint16_t> field_ids() const;

  /// Canonical encoding: fields in ascending identifier order.
  [[nodiscard]] const ByteVector& encode() const noexcept { return encoded_; }

 private:
  void rebuild();
  [[nodiscard]] const ByteVector* find(std::uint16_t field) const noexcept;

  std::map<std::uint16_t, ByteVector> fields_;
  ByteVector encoded_;
};

/// Message payloads exchanged by the coordinator and its clients. Each structure maps onto one
/// canonical field bag; the field identifiers are stable and documented in the README.
struct RegistrationPayload {
  std::uint16_t role = 0;  ///< 0 = client, 1 = publisher
  PublisherIdentity identity;
  AuthorityScope scope;
  std::uint16_t protocol_version = kWireProtocolVersion;
};

struct HelloAckPayload {
  CoordinatorEpoch epoch;
  bool accepted = false;
  std::uint32_t max_frame_bytes = 0;
  std::uint16_t protocol_version = kWireProtocolVersion;
  std::string detail;
};

struct PublicationPayload {
  LineageKey key;
  RouteGeneration route_generation;
  Digest route_state_digest;
  ReasonCode reason = ReasonCode::InitialRoute;
  SourceClass source = SourceClass::RouteFabric;
  std::optional<RootReason> root_reason;
  EvidenceVector evidence;
  AuthorityContext authority;
  Bindings bindings;
  std::vector<EdgeSpec> edges;
};

struct AdministrativePayload {
  LineageKey key;
  ProvenanceNodeId target;
  ReasonCode reason = ReasonCode::AdminWithdrawal;
  SourceClass source = SourceClass::Administrative;
  EvidenceVector evidence;
  AuthorityContext authority;
  Bindings bindings;
  Digest completion_evidence;
  bool allow_non_current_target = false;
};

struct CorrectionPayload {
  LineageKey key;
  ProvenanceNodeId target;
  Digest route_state_digest;
  SourceClass source = SourceClass::Administrative;
  EvidenceVector evidence;
  AuthorityContext authority;
  Bindings bindings;
};

struct DeclarationPayload {
  LineageKey key;
  NodeKind kind = NodeKind::PathAuthorization;
  RouteId route;
  RouteGeneration route_generation;
  ReasonCode reason = ReasonCode::Declaration;
  SourceClass source = SourceClass::PathAuthority;
  EvidenceVector evidence;
  AuthorityContext authority;
  Bindings bindings;
};

struct LinkPayload {
  LineageKey key;
  EdgeType type = EdgeType::AuthorizedBy;
  ProvenanceNodeId from;
  ProvenanceNodeId to;
  ReasonCode reason = ReasonCode::Declaration;
  SourceClass source = SourceClass::PathAuthority;
  EvidenceVector evidence;
  AuthorityContext authority;
};

struct DependencyPayload {
  DependencyNotification notification;
};

struct FencePayload {
  PublisherId publisher;
  WorkerBootId boot;
  AuthorityContext authority;
};

struct QueryPayload {
  RouteLineageId lineage;
  ProvenanceNodeId node;
  TraversalDirection direction = TraversalDirection::Outgoing;
  TraversalBounds bounds;
  ExplainMode mode = ExplainMode::ImmediateCause;
};

[[nodiscard]] Status encode_registration(const RegistrationPayload& payload, ByteVector& out,
                                         const Limits& limits);
[[nodiscard]] Result<RegistrationPayload> decode_registration(ByteSpan payload, const Limits& limits);
[[nodiscard]] Status encode_hello_ack(const HelloAckPayload& payload, ByteVector& out, const Limits& limits);
[[nodiscard]] Result<HelloAckPayload> decode_hello_ack(ByteSpan payload, const Limits& limits);
[[nodiscard]] Status encode_publication(const PublicationPayload& payload, ByteVector& out,
                                        const Limits& limits);
[[nodiscard]] Result<PublicationPayload> decode_publication(ByteSpan payload, const Limits& limits);
[[nodiscard]] Status encode_administrative(const AdministrativePayload& payload, ByteVector& out,
                                           const Limits& limits);
[[nodiscard]] Result<AdministrativePayload> decode_administrative(ByteSpan payload, const Limits& limits);
[[nodiscard]] Status encode_correction(const CorrectionPayload& payload, ByteVector& out,
                                       const Limits& limits);
[[nodiscard]] Result<CorrectionPayload> decode_correction(ByteSpan payload, const Limits& limits);
[[nodiscard]] Status encode_declaration(const DeclarationPayload& payload, ByteVector& out,
                                        const Limits& limits);
[[nodiscard]] Result<DeclarationPayload> decode_declaration(ByteSpan payload, const Limits& limits);
[[nodiscard]] Status encode_link(const LinkPayload& payload, ByteVector& out, const Limits& limits);
[[nodiscard]] Result<LinkPayload> decode_link(ByteSpan payload, const Limits& limits);
[[nodiscard]] Status encode_dependency(const DependencyPayload& payload, ByteVector& out,
                                       const Limits& limits);
[[nodiscard]] Result<DependencyPayload> decode_dependency(ByteSpan payload, const Limits& limits);
[[nodiscard]] Status encode_fence(const FencePayload& payload, ByteVector& out, const Limits& limits);
[[nodiscard]] Result<FencePayload> decode_fence(ByteSpan payload, const Limits& limits);
[[nodiscard]] Status encode_query(const QueryPayload& payload, ByteVector& out, const Limits& limits);
[[nodiscard]] Result<QueryPayload> decode_query(ByteSpan payload, const Limits& limits);

/// Response envelope: a structured outcome, a diagnostic detail string and an optional body.
struct ResponsePayload {
  Outcome outcome = Outcome::Ok;
  std::string detail;
  FieldBag body;
};

[[nodiscard]] Status encode_response(const ResponsePayload& payload, ByteVector& out, const Limits& limits);
[[nodiscard]] Result<ResponsePayload> decode_response(ByteSpan payload, const Limits& limits);

/// Response bodies.
[[nodiscard]] Result<Publication> decode_publication_body(const FieldBag& body, const Limits& limits);
void encode_publication_body(const Publication& publication, FieldBag& body);
void encode_lineage_body(const LineageView& view, FieldBag& body);
[[nodiscard]] Result<LineageView> decode_lineage_body(const FieldBag& body, const Limits& limits);
void encode_nodes_body(const std::vector<ProvenanceNode>& nodes, FieldBag& body);
[[nodiscard]] Result<std::vector<ProvenanceNode>> decode_nodes_body(const FieldBag& body,
                                                                    const Limits& limits);
void encode_explanation_body(const Explanation& explanation, FieldBag& body);
[[nodiscard]] Result<Explanation> decode_explanation_body(const FieldBag& body, const Limits& limits);
void encode_snapshot_body(const Snapshot& snapshot, FieldBag& body);
[[nodiscard]] Result<Snapshot> decode_snapshot_body(const FieldBag& body, const Limits& limits);
void encode_watermarks_body(const DependencyWatermarks& marks, FieldBag& body);
[[nodiscard]] Result<DependencyWatermarks> decode_watermarks_body(const FieldBag& body);

}  // namespace route_provenance
