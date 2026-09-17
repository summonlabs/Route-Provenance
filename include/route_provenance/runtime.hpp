// Route Provenance - distributed coordinator runtime (server) and publisher client.
//
// The coordinator owns publication authority for the store it hosts. A publisher session is a
// real OS process connected over a real loopback transport. Connected is not authoritative:
// a session must register with the current coordinator epoch before it may publish, and a
// session that dies is fenced by the coordinator.
//
// This runtime is a single-coordinator authority model. It is not a consensus protocol and it
// makes no split-brain claim.
#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "route_provenance/authority.hpp"
#include "route_provenance/explanation.hpp"
#include "route_provenance/limits.hpp"
#include "route_provenance/result.hpp"
#include "route_provenance/snapshot.hpp"
#include "route_provenance/store.hpp"
#include "route_provenance/wire.hpp"

namespace route_provenance {

struct ServerOptions {
  /// Loopback address to bind. The coordinator never binds a public interface implicitly.
  std::string bind_address = "127.0.0.1";
  /// 0 requests an ephemeral port, which the caller reads back through port().
  std::uint16_t port = 0;
  Limits limits;
  /// Authority granted to client sessions. With fabric scope a client keeps the scope it
  /// requests; otherwise the session is narrowed to this scope.
  AuthorityScope client_scope = AuthorityScope::fabric();
  /// Coordinator authority used for registry operations such as fencing a dead session.
  AuthorityContext coordinator_authority;
};

struct ServerStats {
  std::uint64_t sessions_accepted = 0;
  std::uint64_t sessions_rejected = 0;
  std::uint64_t sessions_closed = 0;
  std::uint64_t frames_received = 0;
  std::uint64_t frames_sent = 0;
  std::uint64_t bytes_received = 0;
  std::uint64_t bytes_sent = 0;
  std::uint64_t publications = 0;
  std::uint64_t queries = 0;
  std::uint64_t protocol_failures = 0;
  std::uint64_t assembly_timeouts = 0;
  std::uint64_t publishers_fenced = 0;
  std::uint64_t active_sessions = 0;
};

/// Coordinator-side runtime. Owns a ProvenanceStore and serves publishers and clients.
class ProvenanceServer {
 public:
  ProvenanceServer(ProvenanceStore& store, ServerOptions options);
  ~ProvenanceServer();
  ProvenanceServer(const ProvenanceServer&) = delete;
  ProvenanceServer& operator=(const ProvenanceServer&) = delete;

  /// Binds, listens and starts the session loop. Returns IoFailure with a diagnostic when the
  /// address cannot be bound.
  [[nodiscard]] Status start(std::string& error);
  [[nodiscard]] Status stop();

  [[nodiscard]] bool running() const noexcept;
  [[nodiscard]] std::uint16_t port() const noexcept;
  [[nodiscard]] std::string endpoint() const;
  [[nodiscard]] ServerStats stats() const;

  /// Advances the coordinator epoch. Every session registered under an older epoch is fenced.
  [[nodiscard]] Status advance_epoch(CoordinatorEpoch epoch);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

struct ClientOptions {
  std::string address = "127.0.0.1";
  std::uint16_t port = 0;
  Limits limits;
};

/// Publisher and query client. Every call is a request/response exchange over one connection.
class ProvenanceClient {
 public:
  explicit ProvenanceClient(ClientOptions options);
  ~ProvenanceClient();
  ProvenanceClient(const ProvenanceClient&) = delete;
  ProvenanceClient& operator=(const ProvenanceClient&) = delete;

  [[nodiscard]] Status connect(std::string& error);
  void close();
  [[nodiscard]] bool connected() const noexcept;

  [[nodiscard]] Result<HelloAckPayload> hello(const RegistrationPayload& registration);
  [[nodiscard]] Result<DependencyWatermarks> watermarks();
  [[nodiscard]] Result<Publication> publish(const PublicationPayload& payload);
  [[nodiscard]] Result<Publication> administrative(MessageId message, const AdministrativePayload& payload);
  [[nodiscard]] Result<Publication> correct(const CorrectionPayload& payload);
  [[nodiscard]] Result<Publication> declare(const DeclarationPayload& payload);
  [[nodiscard]] Result<Publication> link(const LinkPayload& payload);
  [[nodiscard]] Status notify_dependency(const DependencyPayload& payload);
  [[nodiscard]] Status fence(const FencePayload& payload);
  [[nodiscard]] Result<LineageView> query_lineage(RouteLineageId lineage);
  [[nodiscard]] Result<std::vector<ProvenanceNode>> query_traversal(const QueryPayload& payload);
  [[nodiscard]] Result<Explanation> query_cause(const QueryPayload& payload);
  [[nodiscard]] Result<Snapshot> query_snapshot(RouteLineageId lineage);

  [[nodiscard]] CoordinatorEpoch epoch() const noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace route_provenance
