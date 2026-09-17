// Route Provenance - loopback coordinator runtime and publisher client.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "route_provenance/runtime.hpp"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace route_provenance {
namespace {

#if defined(_WIN32)
using NativeSocket = SOCKET;
constexpr NativeSocket kNoSocket = INVALID_SOCKET;
#else
using NativeSocket = int;
constexpr NativeSocket kNoSocket = -1;
#endif

/// Message exchange budget. Exceeding it is an explicit protocol failure, never a silent hang.
constexpr int kExchangeBudgetMs = 20000;
/// Granularity of the session loop. This bounds how quickly a stop request is observed.
constexpr int kLoopTickMs = 20;

struct SocketRuntime {
  SocketRuntime() {
#if defined(_WIN32)
    WSADATA data;
    static_cast<void>(WSAStartup(MAKEWORD(2, 2), &data));
#endif
  }
  ~SocketRuntime() {
#if defined(_WIN32)
    WSACleanup();
#endif
  }
};

void ensure_socket_runtime() {
  static SocketRuntime runtime;
  static_cast<void>(runtime);
}

void close_socket(NativeSocket socket) noexcept {
  if (socket == kNoSocket) {
    return;
  }
#if defined(_WIN32)
  static_cast<void>(closesocket(socket));
#else
  static_cast<void>(::close(socket));
#endif
}

bool set_nonblocking(NativeSocket socket) {
#if defined(_WIN32)
  u_long mode = 1;
  return ioctlsocket(socket, FIONBIO, &mode) == 0;
#else
  const int flags = fcntl(socket, F_GETFL, 0);
  if (flags < 0) {
    return false;
  }
  return fcntl(socket, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

bool wait_ready(NativeSocket socket, bool for_write, int timeout_ms) {
  fd_set set;
  FD_ZERO(&set);
  FD_SET(socket, &set);
  timeval timeout;
  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_usec = (timeout_ms % 1000) * 1000;
#if defined(_WIN32)
  const int result = select(0, for_write ? nullptr : &set, for_write ? &set : nullptr, nullptr, &timeout);
#else
  const int result =
      select(socket + 1, for_write ? nullptr : &set, for_write ? &set : nullptr, nullptr, &timeout);
#endif
  return result > 0;
}

/// Sends the whole buffer, waiting for writability within a fixed budget. A peer that cannot
/// drain a response inside the budget fails the session instead of pinning the loop.
bool send_all(NativeSocket socket, const std::uint8_t* data, std::size_t size) {
  std::size_t sent = 0;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kExchangeBudgetMs);
  while (sent < size) {
    const int chunk = static_cast<int>(std::min<std::size_t>(size - sent, 1U << 16));
#if defined(_WIN32)
    const int result = ::send(socket, reinterpret_cast<const char*>(data + sent), chunk, 0);
#else
    const int result = static_cast<int>(
        ::send(socket, data + sent, static_cast<std::size_t>(chunk), MSG_NOSIGNAL));
#endif
    if (result > 0) {
      sent += static_cast<std::size_t>(result);
      continue;
    }
    if (std::chrono::steady_clock::now() > deadline) {
      return false;
    }
    if (!wait_ready(socket, true, 200)) {
      continue;
    }
  }
  return true;
}

struct SessionState {
  NativeSocket socket = kNoSocket;
  ByteVector input;
  bool assembling = false;
  std::chrono::steady_clock::time_point assembly_started{};
  bool registered = false;
  bool closing = false;
  PublisherIdentity identity;
  AuthorityScope scope;
};

[[nodiscard]] std::uint16_t peek_payload_length(const ByteVector& buffer) {
  if (buffer.size() < 16) {
    return 0;
  }
  const auto* raw = reinterpret_cast<const std::uint8_t*>(buffer.data());
  return static_cast<std::uint16_t>(load_le32(raw + 12));
}

[[nodiscard]] bool valid_magic(const ByteVector& buffer) {
  if (buffer.size() < 2) {
    return true;
  }
  const auto* raw = reinterpret_cast<const std::uint8_t*>(buffer.data());
  return raw[0] == 0x52U && raw[1] == 0x50U;
}

}  // namespace

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

struct ProvenanceServer::Impl {
  ProvenanceStore& store;
  ServerOptions options;
  NativeSocket listener = kNoSocket;
  std::thread loop;
  std::atomic<bool> stop_requested{false};
  std::atomic<bool> is_running{false};
  std::atomic<std::uint64_t> active_sessions{0};
  std::uint16_t bound_port = 0;
  mutable std::mutex stats_mutex;
  ServerStats stats;
  std::vector<std::unique_ptr<SessionState>> sessions;

  Impl(ProvenanceStore& store_ref, ServerOptions opts)
      : store(store_ref), options(std::move(opts)) {}

  void add_stats(const ServerStats& delta) {
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats.sessions_accepted += delta.sessions_accepted;
    stats.sessions_rejected += delta.sessions_rejected;
    stats.sessions_closed += delta.sessions_closed;
    stats.frames_received += delta.frames_received;
    stats.frames_sent += delta.frames_sent;
    stats.bytes_received += delta.bytes_received;
    stats.bytes_sent += delta.bytes_sent;
    stats.publications += delta.publications;
    stats.queries += delta.queries;
    stats.protocol_failures += delta.protocol_failures;
    stats.assembly_timeouts += delta.assembly_timeouts;
    stats.publishers_fenced += delta.publishers_fenced;
  }

  void run();
  void close_session(SessionState& session, bool fence);
  [[nodiscard]] bool send_frame(SessionState& session, const FrameHeader& header, const FieldBag& body);
  [[nodiscard]] bool send_error(SessionState& session, const FrameHeader& header, Outcome outcome,
                                const std::string& detail);
  void handle_frame(SessionState& session, const DecodedFrame& frame);
};

namespace {

[[nodiscard]] FrameHeader response_header(const FrameHeader& request, MessageId message) {
  FrameHeader header;
  header.message = message;
  header.epoch = request.epoch;
  header.publisher = request.publisher;
  header.boot = request.boot;
  header.attempt = request.attempt;
  return header;
}

[[nodiscard]] AuthorityScope narrow_scope(const AuthorityScope& granted, const AuthorityScope& requested) {
  if (granted.kind() == ScopeKind::Fabric) {
    return requested.is_empty() ? granted : requested;
  }
  return granted;
}

}  // namespace

bool ProvenanceServer::Impl::send_frame(SessionState& session, const FrameHeader& header,
                                        const FieldBag& body) {
  ByteVector frame;
  const ByteVector& payload = body.encode();
  const Status encoded =
      encode_frame(header, ByteSpan(payload.data(), payload.size()), options.limits, frame);
  if (!encoded.is_ok()) {
    ServerStats delta;
    delta.protocol_failures += 1;
    add_stats(delta);
    return false;
  }
  if (!send_all(session.socket, reinterpret_cast<const std::uint8_t*>(frame.data()), frame.size())) {
    return false;
  }
  ServerStats delta;
  delta.frames_sent += 1;
  delta.bytes_sent += frame.size();
  add_stats(delta);
  return true;
}

bool ProvenanceServer::Impl::send_error(SessionState& session, const FrameHeader& request,
                                        Outcome outcome, const std::string& detail) {
  ResponsePayload response;
  response.outcome = outcome;
  response.detail = detail;
  ByteVector payload;
  const Status encoded = encode_response(response, payload, options.limits);
  if (!encoded.is_ok()) {
    return false;
  }
  FieldBag body;
  const Status decoded_body = [&]() {
    const Result<FieldBag> decoded = FieldBag::decode(ByteSpan(payload.data(), payload.size()),
                                                      options.limits);
    if (!decoded.has_value()) {
      return Status::failure(decoded.outcome(), decoded.detail());
    }
    body = decoded.value();
    return Status::ok();
  }();
  if (!decoded_body.is_ok()) {
    return false;
  }
  return send_frame(session, response_header(request, MessageId::Error), body);
}

void ProvenanceServer::Impl::close_session(SessionState& session, bool fence) {
  if (session.socket != kNoSocket) {
    close_socket(session.socket);
    session.socket = kNoSocket;
  }
  ServerStats delta;
  delta.sessions_closed += 1;
  if (fence && session.registered && options.coordinator_authority.has_identity()) {
    const Status fenced = store.fence_publisher(session.identity.publisher, session.identity.boot,
                                                options.coordinator_authority);
    if (fenced.outcome() == Outcome::Ok || fenced.outcome() == Outcome::Updated) {
      delta.publishers_fenced += 1;
    }
  }
  add_stats(delta);
  active_sessions.fetch_sub(1);
}

void ProvenanceServer::Impl::handle_frame(SessionState& session, const DecodedFrame& frame) {
  ServerStats delta;
  delta.frames_received += 1;
  add_stats(delta);

  const FrameHeader& header = frame.header;
  const ByteSpan payload(frame.payload.data(), frame.payload.size());

  if (header.message == MessageId::Ping) {
    FieldBag body;
    static_cast<void>(send_frame(session, response_header(header, MessageId::Pong), body));
    return;
  }
  if (header.message == MessageId::Bye) {
    session.closing = true;
    return;
  }

  const bool is_registration =
      header.message == MessageId::Hello || header.message == MessageId::RegisterPublisher;
  if (is_registration) {
    const Result<RegistrationPayload> registration = decode_registration(payload, options.limits);
    if (!registration.has_value()) {
      static_cast<void>(send_error(session, header, registration.outcome(), registration.detail()));
      session.closing = true;
      return;
    }
    HelloAckPayload ack;
    ack.protocol_version = kWireProtocolVersion;
    ack.max_frame_bytes = options.limits.max_frame_bytes;
    const Result<DependencyWatermarks> marks = store.watermarks();
    ack.epoch = marks.has_value() ? marks.value().epoch : CoordinatorEpoch{};
    if (registration->protocol_version != kWireProtocolVersion) {
      ack.accepted = false;
      ack.detail = "wire protocol version mismatch";
    } else {
      const AuthorityScope granted = narrow_scope(options.client_scope, registration->scope);
      const Result<PublisherRecord> record = store.register_publisher(registration->identity, granted);
      if (record.has_value()) {
        session.registered = true;
        session.identity = registration->identity;
        session.scope = record.value().scope;
        ack.accepted = true;
        ack.detail = "registered";
      } else {
        ack.accepted = false;
        ack.detail = std::string(to_string(record.outcome())) + ": " + record.detail();
        ServerStats rejected;
        rejected.sessions_rejected += 1;
        add_stats(rejected);
      }
    }
    ByteVector encoded;
    const Status status = encode_hello_ack(ack, encoded, options.limits);
    if (!status.is_ok()) {
      session.closing = true;
      return;
    }
    const Result<FieldBag> body = FieldBag::decode(ByteSpan(encoded.data(), encoded.size()),
                                                   options.limits);
    if (!body.has_value() ||
        !send_frame(session, response_header(header, MessageId::HelloAck), body.value())) {
      session.closing = true;
      return;
    }
    if (!ack.accepted) {
      session.closing = true;
    }
    return;
  }

  if (!session.registered) {
    static_cast<void>(send_error(session, header, Outcome::Unauthorized,
                                 "session is not registered with the coordinator"));
    session.closing = true;
    return;
  }
  if (header.publisher != session.identity.publisher || header.boot != session.identity.boot) {
    static_cast<void>(send_error(session, header, Outcome::Unauthorized,
                                 "frame identity does not match the registered session"));
    session.closing = true;
    return;
  }

  const auto publish_response = [&](const Result<Publication>& result) {
    ByteVector encoded;
    if (result.has_value() || outcome_is_stale(result.outcome()) ||
        result.outcome() == Outcome::Duplicate || result.outcome() == Outcome::Idempotent) {
      ResponsePayload response;
      response.outcome = result.outcome();
      response.detail = result.detail();
      if (result.has_value()) {
        encode_publication_body(result.value(), response.body);
      }
      const Status status = encode_response(response, encoded, options.limits);
      if (!status.is_ok()) {
        return;
      }
      const Result<FieldBag> body =
          FieldBag::decode(ByteSpan(encoded.data(), encoded.size()), options.limits);
      if (!body.has_value()) {
        return;
      }
      static_cast<void>(send_frame(session, response_header(header, MessageId::Result), body.value()));
      ServerStats published;
      published.publications += 1;
      add_stats(published);
      return;
    }
    static_cast<void>(send_error(session, header, result.outcome(), result.detail()));
  };
  static_cast<void>(publish_response);

  const auto query_response = [&](Outcome outcome, const std::string& detail, const FieldBag& body) {
    if (!detail.empty() && !outcome_is_commit(outcome)) {
      static_cast<void>(send_error(session, header, outcome, detail));
      return;
    }
    ResponsePayload response;
    response.outcome = outcome;
    response.detail = detail;
    response.body = body;
    ByteVector encoded;
    const Status status = encode_response(response, encoded, options.limits);
    if (!status.is_ok()) {
      return;
    }
    const Result<FieldBag> decoded =
        FieldBag::decode(ByteSpan(encoded.data(), encoded.size()), options.limits);
    if (!decoded.has_value()) {
      return;
    }
    static_cast<void>(send_frame(session, response_header(header, MessageId::Result), decoded.value()));
    ServerStats queried;
    queried.queries += 1;
    add_stats(queried);
  };

  switch (header.message) {
    case MessageId::PublishProvenance:
    case MessageId::Supersede: {
      const Result<PublicationPayload> decoded = decode_publication(payload, options.limits);
      if (!decoded.has_value()) {
        static_cast<void>(send_error(session, header, decoded.outcome(), decoded.detail()));
        return;
      }
      PublishRouteRequest request;
      request.key = decoded->key;
      request.route_generation = decoded->route_generation;
      request.route_state_digest = decoded->route_state_digest;
      request.reason = header.message == MessageId::Supersede ? ReasonCode::RouteReplaced : decoded->reason;
      request.source = decoded->source;
      request.root_reason = decoded->root_reason;
      request.evidence = decoded->evidence;
      request.authority = decoded->authority;
      request.authority.publisher = session.identity;
      request.bindings = decoded->bindings;
      request.edges = decoded->edges;
      publish_response(store.publish_route(request));
      return;
    }
    case MessageId::Withdraw:
    case MessageId::Revoke:
    case MessageId::Retire:
    case MessageId::Revalidate:
    case MessageId::Invalidate: {
      const Result<AdministrativePayload> decoded = decode_administrative(payload, options.limits);
      if (!decoded.has_value()) {
        static_cast<void>(send_error(session, header, decoded.outcome(), decoded.detail()));
        return;
      }
      AdministrativeRequest request;
      request.key = decoded->key;
      request.target = decoded->target;
      request.reason = decoded->reason;
      request.source = decoded->source;
      request.evidence = decoded->evidence;
      request.authority = decoded->authority;
      request.authority.publisher = session.identity;
      request.bindings = decoded->bindings;
      request.completion_evidence = decoded->completion_evidence;
      request.allow_non_current_target = decoded->allow_non_current_target;
      switch (header.message) {
        case MessageId::Withdraw: publish_response(store.withdraw(request)); break;
        case MessageId::Revoke: publish_response(store.revoke(request)); break;
        case MessageId::Retire: publish_response(store.retire(request)); break;
        case MessageId::Revalidate: publish_response(store.revalidate(request)); break;
        default: publish_response(store.invalidate(request)); break;
      }
      return;
    }
    case MessageId::Correct: {
      const Result<CorrectionPayload> decoded = decode_correction(payload, options.limits);
      if (!decoded.has_value()) {
        static_cast<void>(send_error(session, header, decoded.outcome(), decoded.detail()));
        return;
      }
      CorrectionRequest request;
      request.key = decoded->key;
      request.target = decoded->target;
      request.route_state_digest = decoded->route_state_digest;
      request.source = decoded->source;
      request.evidence = decoded->evidence;
      request.authority = decoded->authority;
      request.authority.publisher = session.identity;
      request.bindings = decoded->bindings;
      publish_response(store.correct(request));
      return;
    }
    case MessageId::DeclareSource: {
      const Result<DeclarationPayload> decoded = decode_declaration(payload, options.limits);
      if (!decoded.has_value()) {
        static_cast<void>(send_error(session, header, decoded.outcome(), decoded.detail()));
        return;
      }
      DeclarationRequest request;
      request.key = decoded->key;
      request.kind = decoded->kind;
      request.route = decoded->route;
      request.route_generation = decoded->route_generation;
      request.reason = decoded->reason;
      request.source = decoded->source;
      request.evidence = decoded->evidence;
      request.authority = decoded->authority;
      request.authority.publisher = session.identity;
      request.bindings = decoded->bindings;
      publish_response(store.declare(request));
      return;
    }
    case MessageId::LinkDerivation: {
      const Result<LinkPayload> decoded = decode_link(payload, options.limits);
      if (!decoded.has_value()) {
        static_cast<void>(send_error(session, header, decoded.outcome(), decoded.detail()));
        return;
      }
      LinkDerivationRequest request;
      request.key = decoded->key;
      request.type = decoded->type;
      request.from = decoded->from;
      request.to = decoded->to;
      request.reason = decoded->reason;
      request.source = decoded->source;
      request.evidence = decoded->evidence;
      request.authority = decoded->authority;
      request.authority.publisher = session.identity;
      publish_response(store.link_derivation(request));
      return;
    }
    case MessageId::NotifyDependency: {
      const Result<DependencyPayload> decoded = decode_dependency(payload, options.limits);
      if (!decoded.has_value()) {
        static_cast<void>(send_error(session, header, decoded.outcome(), decoded.detail()));
        return;
      }
      DependencyNotification notification = decoded->notification;
      notification.authority.publisher = session.identity;
      const Status status = store.notify_dependency(notification);
      if (!outcome_is_rejection(status.outcome())) {
        query_response(status.outcome(), status.detail(), FieldBag{});
      } else {
        static_cast<void>(send_error(session, header, status.outcome(), status.detail()));
      }
      return;
    }
    case MessageId::FenceNotice: {
      const Result<FencePayload> decoded = decode_fence(payload, options.limits);
      if (!decoded.has_value()) {
        static_cast<void>(send_error(session, header, decoded.outcome(), decoded.detail()));
        return;
      }
      const Status status = store.fence_publisher(decoded->publisher, decoded->boot, decoded->authority);
      if (!outcome_is_rejection(status.outcome())) {
        query_response(status.outcome(), status.detail(), FieldBag{});
      } else {
        static_cast<void>(send_error(session, header, status.outcome(), status.detail()));
      }
      return;
    }
    case MessageId::QueryLineage: {
      const Result<QueryPayload> decoded = decode_query(payload, options.limits);
      if (!decoded.has_value()) {
        static_cast<void>(send_error(session, header, decoded.outcome(), decoded.detail()));
        return;
      }
      const Result<LineageView> view = store.lineage(decoded->lineage);
      if (!view.has_value()) {
        static_cast<void>(send_error(session, header, view.outcome(), view.detail()));
        return;
      }
      FieldBag body;
      encode_lineage_body(view.value(), body);
      query_response(Outcome::Ok, std::string{}, body);
      return;
    }
    case MessageId::QueryAncestry: {
      const Result<QueryPayload> decoded = decode_query(payload, options.limits);
      if (!decoded.has_value()) {
        static_cast<void>(send_error(session, header, decoded.outcome(), decoded.detail()));
        return;
      }
      const Result<TraversalResult> traversal =
          decoded->direction == TraversalDirection::Outgoing
              ? store.ancestors(decoded->node, decoded->bounds)
              : store.descendants(decoded->node, decoded->bounds);
      if (!traversal.has_value()) {
        static_cast<void>(send_error(session, header, traversal.outcome(), traversal.detail()));
        return;
      }
      std::vector<ProvenanceNode> nodes;
      for (const TraversalEntry& entry : traversal.value().nodes) {
        nodes.push_back(entry.node);
      }
      FieldBag body;
      encode_nodes_body(nodes, body);
      query_response(Outcome::Ok, std::string{}, body);
      return;
    }
    case MessageId::QueryCause: {
      const Result<QueryPayload> decoded = decode_query(payload, options.limits);
      if (!decoded.has_value()) {
        static_cast<void>(send_error(session, header, decoded.outcome(), decoded.detail()));
        return;
      }
      ExplainRequest request;
      request.subject = decoded->node;
      request.mode = decoded->mode;
      request.max_depth = decoded->bounds.max_depth;
      request.max_nodes = decoded->bounds.max_results;
      const Result<Explanation> explanation = store.explain(request);
      if (!explanation.has_value()) {
        static_cast<void>(send_error(session, header, explanation.outcome(), explanation.detail()));
        return;
      }
      FieldBag body;
      encode_explanation_body(explanation.value(), body);
      query_response(Outcome::Ok, std::string{}, body);
      return;
    }
    case MessageId::SnapshotRequest: {
      const Result<QueryPayload> decoded = decode_query(payload, options.limits);
      if (!decoded.has_value()) {
        static_cast<void>(send_error(session, header, decoded.outcome(), decoded.detail()));
        return;
      }
      SnapshotOptions snapshot_options;
      snapshot_options.max_nodes = decoded->bounds.max_results;
      const Result<Snapshot> snapshot = store.snapshot(decoded->lineage, snapshot_options);
      if (!snapshot.has_value()) {
        static_cast<void>(send_error(session, header, snapshot.outcome(), snapshot.detail()));
        return;
      }
      FieldBag body;
      encode_snapshot_body(snapshot.value(), body);
      query_response(Outcome::Ok, std::string{}, body);
      return;
    }
    case MessageId::QueryWatermarks: {
      const Result<DependencyWatermarks> marks = store.watermarks();
      FieldBag body;
      encode_watermarks_body(marks.value(), body);
      query_response(Outcome::Ok, std::string{}, body);
      return;
    }
    default: {
      static_cast<void>(send_error(session, header, Outcome::ProtocolFailure,
                                   "message is not accepted by the coordinator"));
      return;
    }
  }
}

void ProvenanceServer::Impl::run() {
  while (!stop_requested.load()) {
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(listener, &readable);
    NativeSocket highest = listener;
    for (const std::unique_ptr<SessionState>& session : sessions) {
      if (session->socket == kNoSocket) {
        continue;
      }
      FD_SET(session->socket, &readable);
      if (session->socket > highest) {
        highest = session->socket;
      }
    }
    timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = kLoopTickMs * 1000;
#if defined(_WIN32)
    const int ready = select(0, &readable, nullptr, nullptr, &timeout);
#else
    const int ready = select(static_cast<int>(highest) + 1, &readable, nullptr, nullptr, &timeout);
#endif
    if (ready < 0) {
      ServerStats delta;
      delta.protocol_failures += 1;
      add_stats(delta);
      break;
    }
    if (ready > 0 && FD_ISSET(listener, &readable)) {
      while (true) {
        sockaddr_in address{};
#if defined(_WIN32)
        int address_length = static_cast<int>(sizeof(address));
#else
        socklen_t address_length = sizeof(address);
#endif
        const NativeSocket accepted =
            accept(listener, reinterpret_cast<sockaddr*>(&address), &address_length);
        if (accepted == kNoSocket) {
          break;
        }
        if (sessions.size() >= options.limits.max_sessions) {
          close_socket(accepted);
          ServerStats delta;
          delta.sessions_rejected += 1;
          add_stats(delta);
          continue;
        }
        if (!set_nonblocking(accepted)) {
          close_socket(accepted);
          ServerStats delta;
          delta.sessions_rejected += 1;
          add_stats(delta);
          continue;
        }
        const int enabled = 1;
        static_cast<void>(setsockopt(accepted, IPPROTO_TCP, TCP_NODELAY,
                                     reinterpret_cast<const char*>(&enabled), sizeof(enabled)));
        auto session = std::make_unique<SessionState>();
        session->socket = accepted;
        sessions.push_back(std::move(session));
        active_sessions.fetch_add(1);
        ServerStats delta;
        delta.sessions_accepted += 1;
        add_stats(delta);
      }
    }
    if (ready > 0) {
      for (std::unique_ptr<SessionState>& session : sessions) {
        if (session->socket == kNoSocket || !FD_ISSET(session->socket, &readable)) {
          continue;
        }
        bool peer_closed = false;
        while (true) {
          std::uint8_t buffer[8192];
#if defined(_WIN32)
          const int received = recv(session->socket, reinterpret_cast<char*>(buffer),
                                    static_cast<int>(sizeof(buffer)), 0);
#else
          const ssize_t received = recv(session->socket, buffer, sizeof(buffer), 0);
#endif
          if (received > 0) {
            session->input.insert(session->input.end(),
                                  reinterpret_cast<std::byte*>(buffer),
                                  reinterpret_cast<std::byte*>(buffer) + received);
            ServerStats delta;
            delta.bytes_received += static_cast<std::uint64_t>(received);
            add_stats(delta);
            continue;
          }
          if (received == 0) {
            peer_closed = true;
          }
          break;
        }
        if (peer_closed) {
          session->closing = true;
        }
      }
    }

    // Independent liveness probe. Windows does not guarantee that a peer which vanished
    // without a clean shutdown makes its socket select-readable, so every session is also
    // probed with a one-byte peek: a graceful close reports zero, an aborted connection
    // reports a connection error, and an idle session reports neither.
    for (std::unique_ptr<SessionState>& session : sessions) {
      if (session->socket == kNoSocket || session->closing) {
        continue;
      }
      char probe = 0;
      const int peeked = recv(session->socket, &probe, 1, MSG_PEEK);
      if (peeked == 0) {
        session->closing = true;
        continue;
      }
      if (peeked < 0) {
#if defined(_WIN32)
        const int error = WSAGetLastError();
        const bool would_block = error == WSAEWOULDBLOCK || error == WSAEINTR;
#else
        const int error = errno;
        const bool would_block = error == EAGAIN || error == EWOULDBLOCK || error == EINTR;
#endif
        if (!would_block) {
          session->closing = true;
        }
      }
    }

    const auto now = std::chrono::steady_clock::now();
    for (std::unique_ptr<SessionState>& session : sessions) {
      if (session->socket == kNoSocket) {
        continue;
      }
      if (!session->closing && !session->input.empty() && !session->assembling) {
        // A peer that sends anything at all and then stalls is assembled against the same
        // deadline as a peer that sends a partial frame header.
        session->assembling = true;
        session->assembly_started = now;
      }
      while (!session->closing && session->input.size() >= 16) {
        if (!valid_magic(session->input)) {
          ServerStats delta;
          delta.protocol_failures += 1;
          add_stats(delta);
          session->closing = true;
          break;
        }
        const std::uint16_t payload_length = peek_payload_length(session->input);
        const std::size_t frame_size =
            kFrameHeaderBytes + static_cast<std::size_t>(payload_length) + kFrameTrailerBytes;
        if (frame_size > options.limits.max_frame_bytes) {
          ServerStats delta;
          delta.protocol_failures += 1;
          add_stats(delta);
          session->closing = true;
          break;
        }
        if (session->input.size() < frame_size) {
          if (!session->assembling) {
            session->assembling = true;
            session->assembly_started = now;
          }
          break;
        }
        session->assembling = false;
        const ByteSpan frame(session->input.data(), frame_size);
        const Result<DecodedFrame> decoded = decode_frame(frame, options.limits);
        session->input.erase(session->input.begin(),
                             session->input.begin() + static_cast<std::ptrdiff_t>(frame_size));
        if (!decoded.has_value()) {
          ServerStats delta;
          delta.protocol_failures += 1;
          add_stats(delta);
          static_cast<void>(send_error(*session, FrameHeader{}, decoded.outcome(), decoded.detail()));
          session->closing = true;
          break;
        }
        handle_frame(*session, decoded.value());
      }
      if (session->assembling) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - session->assembly_started);
        if (elapsed.count() > static_cast<long long>(options.limits.max_frame_assembly_ms)) {
          // A peer that never completes a frame is failed explicitly instead of pinning the
          // session: partial-frame defence is product behaviour, not a test timeout.
          ServerStats delta;
          delta.assembly_timeouts += 1;
          add_stats(delta);
          session->closing = true;
        }
      }
    }

    for (std::unique_ptr<SessionState>& session : sessions) {
      if (session->closing && session->socket != kNoSocket) {
        close_session(*session, true);
      }
    }
    sessions.erase(std::remove_if(sessions.begin(), sessions.end(),
                                  [](const std::unique_ptr<SessionState>& session) {
                                    return session->socket == kNoSocket;
                                  }),
                   sessions.end());
  }

  for (std::unique_ptr<SessionState>& session : sessions) {
    if (session->socket != kNoSocket) {
      close_session(*session, true);
    }
  }
  sessions.clear();
  is_running.store(false);
}

ProvenanceServer::ProvenanceServer(ProvenanceStore& store, ServerOptions options)
    : impl_(std::make_unique<Impl>(store, std::move(options))) {}

ProvenanceServer::~ProvenanceServer() { static_cast<void>(stop()); }

Status ProvenanceServer::start(std::string& error) {
  if (impl_->is_running.load()) {
    error = "server is already running";
    return Status::failure(Outcome::MalformedRequest, error);
  }
  ensure_socket_runtime();
  impl_->listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (impl_->listener == kNoSocket) {
    error = "cannot create the listening socket";
    return Status::failure(Outcome::IoFailure, error);
  }
  const int enabled = 1;
  static_cast<void>(setsockopt(impl_->listener, SOL_SOCKET, SO_REUSEADDR,
                               reinterpret_cast<const char*>(&enabled), sizeof(enabled)));
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(impl_->options.port);
  if (impl_->options.bind_address != "127.0.0.1") {
    // Only explicit loopback aliases are accepted; the coordinator does not bind public
    // interfaces implicitly.
    if (inet_pton(AF_INET, impl_->options.bind_address.c_str(), &address.sin_addr) != 1) {
      close_socket(impl_->listener);
      impl_->listener = kNoSocket;
      error = "bind address must be a valid IPv4 literal";
      return Status::failure(Outcome::MalformedRequest, error);
    }
  } else {
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  }
  if (bind(impl_->listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    close_socket(impl_->listener);
    impl_->listener = kNoSocket;
    error = "cannot bind the coordinator endpoint";
    return Status::failure(Outcome::IoFailure, error);
  }
  if (listen(impl_->listener, 16) != 0) {
    close_socket(impl_->listener);
    impl_->listener = kNoSocket;
    error = "cannot listen on the coordinator endpoint";
    return Status::failure(Outcome::IoFailure, error);
  }
  sockaddr_in bound{};
#if defined(_WIN32)
  int bound_length = static_cast<int>(sizeof(bound));
#else
  socklen_t bound_length = sizeof(bound);
#endif
  if (getsockname(impl_->listener, reinterpret_cast<sockaddr*>(&bound), &bound_length) != 0) {
    close_socket(impl_->listener);
    impl_->listener = kNoSocket;
    error = "cannot determine the bound coordinator port";
    return Status::failure(Outcome::IoFailure, error);
  }
  if (!set_nonblocking(impl_->listener)) {
    close_socket(impl_->listener);
    impl_->listener = kNoSocket;
    error = "cannot switch the listening socket to non-blocking mode";
    return Status::failure(Outcome::IoFailure, error);
  }
  impl_->bound_port = ntohs(bound.sin_port);
  impl_->stop_requested.store(false);
  impl_->is_running.store(true);
  impl_->loop = std::thread([this]() { impl_->run(); });
  return Status::ok();
}

Status ProvenanceServer::stop() {
  if (!impl_->is_running.load() && !impl_->loop.joinable()) {
    return Status::ok(Outcome::Idempotent, "server is not running");
  }
  impl_->stop_requested.store(true);
  if (impl_->loop.joinable()) {
    if (impl_->loop.get_id() == std::this_thread::get_id()) {
      return Status::failure(Outcome::MalformedRequest, "the session loop cannot stop itself");
    }
    impl_->loop.join();
  }
  if (impl_->listener != kNoSocket) {
    close_socket(impl_->listener);
    impl_->listener = kNoSocket;
  }
  return Status::ok();
}

bool ProvenanceServer::running() const noexcept { return impl_->is_running.load(); }

std::uint16_t ProvenanceServer::port() const noexcept { return impl_->bound_port; }

std::string ProvenanceServer::endpoint() const {
  return impl_->options.bind_address + ":" + std::to_string(impl_->bound_port);
}

ServerStats ProvenanceServer::stats() const {
  std::lock_guard<std::mutex> lock(impl_->stats_mutex);
  ServerStats snapshot = impl_->stats;
  snapshot.active_sessions = impl_->active_sessions.load();
  return snapshot;
}

Status ProvenanceServer::advance_epoch(CoordinatorEpoch epoch) {
  if (!impl_->is_running.load()) {
    return Status::failure(Outcome::MalformedRequest, "server is not running");
  }
  const Status advanced = impl_->store.advance_epoch(epoch, impl_->options.coordinator_authority);
  if (!advanced.is_ok()) {
    return advanced;
  }
  // Sessions registered under the previous epoch are fenced; they must register again.
  {
    std::lock_guard<std::mutex> guard(impl_->stats_mutex);
    impl_->options.coordinator_authority.publisher.epoch = epoch;
  }
  return Status::ok(Outcome::Updated, "coordinator epoch advanced");
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

struct ProvenanceClient::Impl {
  ClientOptions options;
  NativeSocket socket = kNoSocket;
  CoordinatorEpoch epoch;
  PublisherIdentity identity;
  ByteVector input;

  explicit Impl(ClientOptions opts) : options(std::move(opts)) {}

  [[nodiscard]] Status exchange(MessageId message, const ByteVector& payload, DecodedFrame& response);
};

Status ProvenanceClient::Impl::exchange(MessageId message, const ByteVector& payload,
                                        DecodedFrame& response) {
  if (socket == kNoSocket) {
    return Status::failure(Outcome::ProtocolFailure, "client is not connected");
  }
  FrameHeader header;
  header.message = message;
  header.epoch = epoch;
  header.publisher = identity.publisher;
  header.boot = identity.boot;
  header.attempt = MutationAttemptId::from_value(0);
  ByteVector frame;
  const Status encoded = encode_frame(header, ByteSpan(payload.data(), payload.size()),
                                      options.limits, frame);
  if (!encoded.is_ok()) {
    return encoded;
  }
  if (!send_all(socket, reinterpret_cast<const std::uint8_t*>(frame.data()), frame.size())) {
    return Status::failure(Outcome::ProtocolFailure, "cannot send the request to the coordinator");
  }
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kExchangeBudgetMs);
  while (true) {
    if (input.size() >= 16) {
      const std::uint32_t payload_length = [&]() {
        const auto* raw = reinterpret_cast<const std::uint8_t*>(input.data());
        return load_le32(raw + 12);
      }();
      const std::size_t frame_size =
          kFrameHeaderBytes + static_cast<std::size_t>(payload_length) + kFrameTrailerBytes;
      if (frame_size > options.limits.max_frame_bytes) {
        return Status::failure(Outcome::ResourceLimit, "coordinator response exceeds max_frame_bytes");
      }
      if (input.size() >= frame_size) {
        const Result<DecodedFrame> decoded =
            decode_frame(ByteSpan(input.data(), frame_size), options.limits);
        input.erase(input.begin(), input.begin() + static_cast<std::ptrdiff_t>(frame_size));
        if (!decoded.has_value()) {
          return Status::failure(decoded.outcome(), decoded.detail());
        }
        response = decoded.value();
        return Status::ok();
      }
    }
    if (std::chrono::steady_clock::now() > deadline) {
      return Status::failure(Outcome::ProtocolFailure,
                             "coordinator did not complete a response within the exchange budget");
    }
    if (!wait_ready(socket, false, 200)) {
      continue;
    }
    std::uint8_t buffer[8192];
#if defined(_WIN32)
    const int received = recv(socket, reinterpret_cast<char*>(buffer), static_cast<int>(sizeof(buffer)), 0);
#else
    const ssize_t received = recv(socket, buffer, sizeof(buffer), 0);
#endif
    if (received > 0) {
      input.insert(input.end(), reinterpret_cast<std::byte*>(buffer),
                   reinterpret_cast<std::byte*>(buffer) + received);
      continue;
    }
    if (received == 0) {
      return Status::failure(Outcome::ProtocolFailure, "coordinator closed the session");
    }
    return Status::failure(Outcome::ProtocolFailure, "coordinator session failed");
  }
}

ProvenanceClient::ProvenanceClient(ClientOptions options) : impl_(std::make_unique<Impl>(std::move(options))) {}

ProvenanceClient::~ProvenanceClient() { close(); }

Status ProvenanceClient::connect(std::string& error) {
  if (impl_->socket != kNoSocket) {
    error = "client is already connected";
    return Status::failure(Outcome::MalformedRequest, error);
  }
  ensure_socket_runtime();
  NativeSocket socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socket == kNoSocket) {
    error = "cannot create the client socket";
    return Status::failure(Outcome::IoFailure, error);
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(impl_->options.port);
  if (inet_pton(AF_INET, impl_->options.address.c_str(), &address.sin_addr) != 1) {
    close_socket(socket);
    error = "coordinator address must be a valid IPv4 literal";
    return Status::failure(Outcome::MalformedRequest, error);
  }
  if (::connect(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    close_socket(socket);
    error = "cannot connect to the coordinator";
    return Status::failure(Outcome::IoFailure, error);
  }
  const int enabled = 1;
  static_cast<void>(setsockopt(socket, IPPROTO_TCP, TCP_NODELAY,
                               reinterpret_cast<const char*>(&enabled), sizeof(enabled)));
  impl_->socket = socket;
  return Status::ok();
}

void ProvenanceClient::close() {
  if (impl_->socket != kNoSocket) {
    close_socket(impl_->socket);
    impl_->socket = kNoSocket;
  }
  impl_->input.clear();
}

bool ProvenanceClient::connected() const noexcept { return impl_->socket != kNoSocket; }

CoordinatorEpoch ProvenanceClient::epoch() const noexcept { return impl_->epoch; }

Result<HelloAckPayload> ProvenanceClient::hello(const RegistrationPayload& registration) {
  ByteVector payload;
  const Status encoded = encode_registration(registration, payload, impl_->options.limits);
  if (!encoded.is_ok()) {
    return Result<HelloAckPayload>::failure(encoded.outcome(), encoded.detail());
  }
  DecodedFrame response;
  const Status exchanged =
      impl_->exchange(MessageId::Hello, payload, response);
  if (!exchanged.is_ok()) {
    return Result<HelloAckPayload>::failure(exchanged.outcome(), exchanged.detail());
  }
  const Result<HelloAckPayload> ack = decode_hello_ack(
      ByteSpan(response.payload.data(), response.payload.size()), impl_->options.limits);
  if (!ack.has_value()) {
    return ack;
  }
  if (ack->accepted) {
    impl_->epoch = registration.identity.epoch;
    impl_->identity = registration.identity;
  }
  return ack;
}

Result<DependencyWatermarks> ProvenanceClient::watermarks() {
  ByteVector payload;
  DecodedFrame response;
  const Status exchanged = impl_->exchange(MessageId::QueryWatermarks, payload, response);
  if (!exchanged.is_ok()) {
    return Result<DependencyWatermarks>::failure(exchanged.outcome(), exchanged.detail());
  }
  const Result<ResponsePayload> decoded = decode_response(
      ByteSpan(response.payload.data(), response.payload.size()), impl_->options.limits);
  if (!decoded.has_value()) {
    return Result<DependencyWatermarks>::failure(decoded.outcome(), decoded.detail());
  }
  if (decoded->outcome != Outcome::Ok) {
    return Result<DependencyWatermarks>::failure(decoded->outcome, decoded->detail);
  }
  return decode_watermarks_body(decoded->body);
}

Result<Publication> ProvenanceClient::publish(const PublicationPayload& payload) {
  ByteVector encoded;
  const Status status = encode_publication(payload, encoded, impl_->options.limits);
  if (!status.is_ok()) {
    return Result<Publication>::failure(status.outcome(), status.detail());
  }
  DecodedFrame response;
  const Status exchanged = impl_->exchange(MessageId::PublishProvenance, encoded, response);
  if (!exchanged.is_ok()) {
    return Result<Publication>::failure(exchanged.outcome(), exchanged.detail());
  }
  const Result<ResponsePayload> decoded = decode_response(
      ByteSpan(response.payload.data(), response.payload.size()), impl_->options.limits);
  if (!decoded.has_value()) {
    return Result<Publication>::failure(decoded.outcome(), decoded.detail());
  }
  if (!decoded->body.has(1)) {
    return Result<Publication>(decoded->outcome, std::nullopt, decoded->detail);
  }
  const Result<Publication> publication =
      decode_publication_body(decoded->body, impl_->options.limits);
  if (!publication.has_value()) {
    return Result<Publication>(decoded->outcome, std::nullopt, decoded->detail);
  }
  return Result<Publication>(decoded->outcome, publication.value(), decoded->detail);
}

Result<Publication> ProvenanceClient::administrative(MessageId message,
                                                     const AdministrativePayload& payload) {
  ByteVector encoded;
  const Status status = encode_administrative(payload, encoded, impl_->options.limits);
  if (!status.is_ok()) {
    return Result<Publication>::failure(status.outcome(), status.detail());
  }
  DecodedFrame response;
  const Status exchanged = impl_->exchange(message, encoded, response);
  if (!exchanged.is_ok()) {
    return Result<Publication>::failure(exchanged.outcome(), exchanged.detail());
  }
  const Result<ResponsePayload> decoded = decode_response(
      ByteSpan(response.payload.data(), response.payload.size()), impl_->options.limits);
  if (!decoded.has_value()) {
    return Result<Publication>::failure(decoded.outcome(), decoded.detail());
  }
  if (!decoded->body.has(1)) {
    return Result<Publication>(decoded->outcome, std::nullopt, decoded->detail);
  }
  const Result<Publication> publication =
      decode_publication_body(decoded->body, impl_->options.limits);
  if (!publication.has_value()) {
    return Result<Publication>(decoded->outcome, std::nullopt, decoded->detail);
  }
  return Result<Publication>(decoded->outcome, publication.value(), decoded->detail);
}

Result<Publication> ProvenanceClient::correct(const CorrectionPayload& payload) {
  ByteVector encoded;
  const Status status = encode_correction(payload, encoded, impl_->options.limits);
  if (!status.is_ok()) {
    return Result<Publication>::failure(status.outcome(), status.detail());
  }
  DecodedFrame response;
  const Status exchanged = impl_->exchange(MessageId::Correct, encoded, response);
  if (!exchanged.is_ok()) {
    return Result<Publication>::failure(exchanged.outcome(), exchanged.detail());
  }
  const Result<ResponsePayload> decoded = decode_response(
      ByteSpan(response.payload.data(), response.payload.size()), impl_->options.limits);
  if (!decoded.has_value()) {
    return Result<Publication>::failure(decoded.outcome(), decoded.detail());
  }
  if (!decoded->body.has(1)) {
    return Result<Publication>(decoded->outcome, std::nullopt, decoded->detail);
  }
  const Result<Publication> publication =
      decode_publication_body(decoded->body, impl_->options.limits);
  if (!publication.has_value()) {
    return Result<Publication>(decoded->outcome, std::nullopt, decoded->detail);
  }
  return Result<Publication>(decoded->outcome, publication.value(), decoded->detail);
}

Result<Publication> ProvenanceClient::declare(const DeclarationPayload& payload) {
  ByteVector encoded;
  const Status status = encode_declaration(payload, encoded, impl_->options.limits);
  if (!status.is_ok()) {
    return Result<Publication>::failure(status.outcome(), status.detail());
  }
  DecodedFrame response;
  const Status exchanged = impl_->exchange(MessageId::DeclareSource, encoded, response);
  if (!exchanged.is_ok()) {
    return Result<Publication>::failure(exchanged.outcome(), exchanged.detail());
  }
  const Result<ResponsePayload> decoded = decode_response(
      ByteSpan(response.payload.data(), response.payload.size()), impl_->options.limits);
  if (!decoded.has_value()) {
    return Result<Publication>::failure(decoded.outcome(), decoded.detail());
  }
  if (!decoded->body.has(1)) {
    return Result<Publication>(decoded->outcome, std::nullopt, decoded->detail);
  }
  const Result<Publication> publication =
      decode_publication_body(decoded->body, impl_->options.limits);
  if (!publication.has_value()) {
    return Result<Publication>(decoded->outcome, std::nullopt, decoded->detail);
  }
  return Result<Publication>(decoded->outcome, publication.value(), decoded->detail);
}

Result<Publication> ProvenanceClient::link(const LinkPayload& payload) {
  ByteVector encoded;
  const Status status = encode_link(payload, encoded, impl_->options.limits);
  if (!status.is_ok()) {
    return Result<Publication>::failure(status.outcome(), status.detail());
  }
  DecodedFrame response;
  const Status exchanged = impl_->exchange(MessageId::LinkDerivation, encoded, response);
  if (!exchanged.is_ok()) {
    return Result<Publication>::failure(exchanged.outcome(), exchanged.detail());
  }
  const Result<ResponsePayload> decoded = decode_response(
      ByteSpan(response.payload.data(), response.payload.size()), impl_->options.limits);
  if (!decoded.has_value()) {
    return Result<Publication>::failure(decoded.outcome(), decoded.detail());
  }
  if (!decoded->body.has(1)) {
    return Result<Publication>(decoded->outcome, std::nullopt, decoded->detail);
  }
  const Result<Publication> publication =
      decode_publication_body(decoded->body, impl_->options.limits);
  if (!publication.has_value()) {
    return Result<Publication>(decoded->outcome, std::nullopt, decoded->detail);
  }
  return Result<Publication>(decoded->outcome, publication.value(), decoded->detail);
}

Status ProvenanceClient::notify_dependency(const DependencyPayload& payload) {
  ByteVector encoded;
  const Status status = encode_dependency(payload, encoded, impl_->options.limits);
  if (!status.is_ok()) {
    return status;
  }
  DecodedFrame response;
  const Status exchanged = impl_->exchange(MessageId::NotifyDependency, encoded, response);
  if (!exchanged.is_ok()) {
    return exchanged;
  }
  const Result<ResponsePayload> decoded = decode_response(
      ByteSpan(response.payload.data(), response.payload.size()), impl_->options.limits);
  if (!decoded.has_value()) {
    return Status::failure(decoded.outcome(), decoded.detail());
  }
  if (decoded->outcome != Outcome::Ok) {
    return Status::failure(decoded->outcome, decoded->detail);
  }
  return Status::ok(decoded->outcome, decoded->detail);
}

Status ProvenanceClient::fence(const FencePayload& payload) {
  ByteVector encoded;
  const Status status = encode_fence(payload, encoded, impl_->options.limits);
  if (!status.is_ok()) {
    return status;
  }
  DecodedFrame response;
  const Status exchanged = impl_->exchange(MessageId::FenceNotice, encoded, response);
  if (!exchanged.is_ok()) {
    return exchanged;
  }
  const Result<ResponsePayload> decoded = decode_response(
      ByteSpan(response.payload.data(), response.payload.size()), impl_->options.limits);
  if (!decoded.has_value()) {
    return Status::failure(decoded.outcome(), decoded.detail());
  }
  if (decoded->outcome != Outcome::Ok) {
    return Status::failure(decoded->outcome, decoded->detail);
  }
  return Status::ok(decoded->outcome, decoded->detail);
}

Result<LineageView> ProvenanceClient::query_lineage(RouteLineageId lineage) {
  QueryPayload query;
  query.lineage = lineage;
  ByteVector encoded;
  const Status status = encode_query(query, encoded, impl_->options.limits);
  if (!status.is_ok()) {
    return Result<LineageView>::failure(status.outcome(), status.detail());
  }
  DecodedFrame response;
  const Status exchanged = impl_->exchange(MessageId::QueryLineage, encoded, response);
  if (!exchanged.is_ok()) {
    return Result<LineageView>::failure(exchanged.outcome(), exchanged.detail());
  }
  const Result<ResponsePayload> decoded = decode_response(
      ByteSpan(response.payload.data(), response.payload.size()), impl_->options.limits);
  if (!decoded.has_value()) {
    return Result<LineageView>::failure(decoded.outcome(), decoded.detail());
  }
  if (decoded->outcome != Outcome::Ok) {
    return Result<LineageView>::failure(decoded->outcome, decoded->detail);
  }
  return decode_lineage_body(decoded->body, impl_->options.limits);
}

Result<std::vector<ProvenanceNode>> ProvenanceClient::query_traversal(const QueryPayload& payload) {
  ByteVector encoded;
  const Status status = encode_query(payload, encoded, impl_->options.limits);
  if (!status.is_ok()) {
    return Result<std::vector<ProvenanceNode>>::failure(status.outcome(), status.detail());
  }
  DecodedFrame response;
  const Status exchanged = impl_->exchange(MessageId::QueryAncestry, encoded, response);
  if (!exchanged.is_ok()) {
    return Result<std::vector<ProvenanceNode>>::failure(exchanged.outcome(), exchanged.detail());
  }
  const Result<ResponsePayload> decoded = decode_response(
      ByteSpan(response.payload.data(), response.payload.size()), impl_->options.limits);
  if (!decoded.has_value()) {
    return Result<std::vector<ProvenanceNode>>::failure(decoded.outcome(), decoded.detail());
  }
  if (decoded->outcome != Outcome::Ok) {
    return Result<std::vector<ProvenanceNode>>::failure(decoded->outcome, decoded->detail);
  }
  return decode_nodes_body(decoded->body, impl_->options.limits);
}

Result<Explanation> ProvenanceClient::query_cause(const QueryPayload& payload) {
  ByteVector encoded;
  const Status status = encode_query(payload, encoded, impl_->options.limits);
  if (!status.is_ok()) {
    return Result<Explanation>::failure(status.outcome(), status.detail());
  }
  DecodedFrame response;
  const Status exchanged = impl_->exchange(MessageId::QueryCause, encoded, response);
  if (!exchanged.is_ok()) {
    return Result<Explanation>::failure(exchanged.outcome(), exchanged.detail());
  }
  const Result<ResponsePayload> decoded = decode_response(
      ByteSpan(response.payload.data(), response.payload.size()), impl_->options.limits);
  if (!decoded.has_value()) {
    return Result<Explanation>::failure(decoded.outcome(), decoded.detail());
  }
  if (decoded->outcome != Outcome::Ok) {
    return Result<Explanation>::failure(decoded->outcome, decoded->detail);
  }
  return decode_explanation_body(decoded->body, impl_->options.limits);
}

Result<Snapshot> ProvenanceClient::query_snapshot(RouteLineageId lineage) {
  QueryPayload query;
  query.lineage = lineage;
  ByteVector encoded;
  const Status status = encode_query(query, encoded, impl_->options.limits);
  if (!status.is_ok()) {
    return Result<Snapshot>::failure(status.outcome(), status.detail());
  }
  DecodedFrame response;
  const Status exchanged = impl_->exchange(MessageId::SnapshotRequest, encoded, response);
  if (!exchanged.is_ok()) {
    return Result<Snapshot>::failure(exchanged.outcome(), exchanged.detail());
  }
  const Result<ResponsePayload> decoded = decode_response(
      ByteSpan(response.payload.data(), response.payload.size()), impl_->options.limits);
  if (!decoded.has_value()) {
    return Result<Snapshot>::failure(decoded.outcome(), decoded.detail());
  }
  if (decoded->outcome != Outcome::Ok) {
    return Result<Snapshot>::failure(decoded->outcome, decoded->detail);
  }
  return decode_snapshot_body(decoded->body, impl_->options.limits);
}

}  // namespace route_provenance
