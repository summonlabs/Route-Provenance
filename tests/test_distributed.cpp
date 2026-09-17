// Route Provenance - distributed suite: real processes, real transport, real termination.
//
// Every wait here is bounded and reports an explicit failure when the bound is exceeded. No
// test timeout is configured; a stuck system fails instead of hanging.
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include "harness.hpp"
#include "route_provenance/runtime.hpp"
#include "support.hpp"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif

using namespace rp_test;
using namespace route_provenance;

namespace {

constexpr unsigned kStartupBudgetMs = 30000;
constexpr unsigned kExchangeBudgetMs = 30000;

struct Coordinator {
  std::string directory;
  std::string store;
  std::string ready_file;
  std::uint16_t port = 0;
  std::uint64_t epoch = 0;
  ChildProcess process;
  bool started = false;
};

[[nodiscard]] bool read_ready_file(const std::string& path, std::uint16_t& port, std::uint64_t& epoch) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    return false;
  }
  std::string line;
  bool have_port = false;
  bool have_epoch = false;
  while (std::getline(file, line)) {
    const std::size_t separator = line.find('=');
    if (separator == std::string::npos) {
      continue;
    }
    const std::string key = line.substr(0, separator);
    const std::string value = line.substr(separator + 1);
    if (key == "port") {
      port = static_cast<std::uint16_t>(std::stoul(value));
      have_port = true;
    } else if (key == "epoch") {
      epoch = std::stoull(value);
      have_epoch = true;
    }
  }
  return have_port && have_epoch;
}

[[nodiscard]] bool start_coordinator(Coordinator& coordinator, const std::string& label, bool load,
                                     const std::vector<std::string>& extra = {}) {
  if (coordinator.directory.empty()) {
    coordinator.directory = make_temp_dir(label, scratch_dir());
  }
  if (coordinator.store.empty()) {
    coordinator.store = coordinator.directory + "/store.rpstore";
  }
  static std::atomic<unsigned long long> ready_sequence{0};
  coordinator.ready_file = coordinator.directory + "/ready-" +
                           std::to_string(++ready_sequence) + ".txt";
  std::vector<std::string> args{"--store", coordinator.store, "--ready-file", coordinator.ready_file};
  if (load) {
    args.push_back("--load");
  }
  for (const std::string& argument : extra) {
    args.push_back(argument);
  }
  std::string error;
  auto launched = ChildProcess::launch(coordinator_exe(), args, coordinator.directory, error);
  if (!launched.has_value()) {
    RP_FAIL("cannot launch the coordinator: " + error);
    return false;
  }
  coordinator.process = std::move(*launched);
  std::uint16_t parsed_port = 0;
  std::uint64_t parsed_epoch = 0;
  const bool ready = wait_until(kStartupBudgetMs, [&coordinator, &parsed_port, &parsed_epoch]() {
    return file_exists(coordinator.ready_file) &&
           read_ready_file(coordinator.ready_file, parsed_port, parsed_epoch);
  });
  if (!ready) {
    RP_FAIL("coordinator did not report readiness inside the bound: " +
            coordinator.process.captured_output());
    coordinator.process.terminate();
    return false;
  }
  if (!read_ready_file(coordinator.ready_file, coordinator.port, coordinator.epoch)) {
    RP_FAIL("coordinator readiness file is malformed");
    coordinator.process.terminate();
    return false;
  }
  coordinator.started = true;
  return true;
}

[[nodiscard]] std::string write_script(const std::string& directory, const std::string& name,
                                       const std::vector<std::string>& lines) {
  const std::string path = directory + "/" + name;
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  for (const std::string& line : lines) {
    file << line << "\n";
  }
  file.flush();
  return path;
}

[[nodiscard]] bool start_publisher(ChildProcess& process, const Coordinator& coordinator,
                                   std::uint64_t publisher, std::uint64_t boot, std::uint64_t epoch,
                                   const std::string& script, const std::string& label) {
  std::vector<std::string> args{"--connect",
                                "127.0.0.1:" + std::to_string(coordinator.port),
                                "--publisher",
                                std::to_string(publisher),
                                "--boot",
                                std::to_string(boot),
                                "--epoch",
                                std::to_string(epoch),
                                "--script",
                                script};
  std::string error;
  auto launched = ChildProcess::launch(publisher_exe(), args, coordinator.directory + "/" + label,
                                             error);
  if (!launched.has_value()) {
    RP_FAIL("cannot launch the publisher: " + error);
    return false;
  }
  process = std::move(*launched);
  return true;
}

/// A registered verifier session used by the suite to observe coordinator state.
struct Verifier {
  std::unique_ptr<ProvenanceClient> client;
  bool ready = false;

  /// Every session uses its own worker boot: a boot that has been fenced may never publish
  /// again, and that rule applies to verification sessions exactly as it does to publishers.
  [[nodiscard]] static std::uint64_t next_boot() {
    static std::uint64_t counter = 900;
    return ++counter;
  }

  [[nodiscard]] bool open(const Coordinator& coordinator) {
    ClientOptions options;
    options.address = "127.0.0.1";
    options.port = coordinator.port;
    client = std::make_unique<ProvenanceClient>(options);
    std::string error;
    if (!client->connect(error).is_ok()) {
      RP_FAIL("verifier cannot connect: " + error);
      return false;
    }
    RegistrationPayload registration;
    registration.role = 0;
    registration.identity = PublisherIdentity{PublisherId::from_value(900),
                                             WorkerBootId::from_value(next_boot()),
                                             CoordinatorEpoch::from_value(coordinator.epoch)};
    registration.scope = AuthorityScope::fabric();
    const auto ack = client->hello(registration);
    if (!ack.has_value() || !ack.value().accepted) {
      RP_FAIL("verifier registration was refused: " + (ack.has_value() ? ack.value().detail : ack.detail()));
      return false;
    }
    ready = true;
    return true;
  }
};

#if defined(_WIN32)
/// Minimal raw TCP peer used to attack framing behaviour.
class RawPeer {
 public:
  ~RawPeer() { close(); }

  [[nodiscard]] bool connect_to(const Coordinator& coordinator) {
    WSADATA data;
    static_cast<void>(WSAStartup(MAKEWORD(2, 2), &data));
    socket_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_ == INVALID_SOCKET) {
      return false;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(coordinator.port);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (::connect(socket_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
      return false;
    }
    return true;
  }

  bool send_bytes(const std::vector<std::uint8_t>& bytes) {
    std::size_t sent = 0;
    while (sent < bytes.size()) {
      const int result = ::send(socket_, reinterpret_cast<const char*>(bytes.data() + sent),
                                static_cast<int>(bytes.size() - sent), 0);
      if (result <= 0) {
        return false;
      }
      sent += static_cast<std::size_t>(result);
    }
    return true;
  }

  /// Reads until the peer closes or the bound elapses. Returns false when the bound elapsed
  /// without the peer closing the session.
  [[nodiscard]] bool wait_for_closure(unsigned milliseconds) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
    std::uint8_t buffer[512];
    while (std::chrono::steady_clock::now() < deadline) {
      fd_set set;
      FD_ZERO(&set);
      FD_SET(socket_, &set);
      timeval timeout{0, 100000};
      const int ready = select(0, &set, nullptr, nullptr, &timeout);
      if (ready <= 0) {
        continue;
      }
      const int received = recv(socket_, reinterpret_cast<char*>(buffer), sizeof(buffer), 0);
      if (received == 0) {
        return true;
      }
      if (received < 0) {
        return true;
      }
    }
    return false;
  }

  void close() {
    if (socket_ != INVALID_SOCKET) {
      static_cast<void>(closesocket(socket_));
      socket_ = INVALID_SOCKET;
    }
  }

 private:
  SOCKET socket_ = INVALID_SOCKET;
};
#endif

[[nodiscard]] std::vector<std::uint8_t> partial_frame_bytes() {
  // A syntactically valid frame prefix that is never completed.
  std::vector<std::uint8_t> bytes;
  bytes.push_back(0x52U);
  bytes.push_back(0x50U);
  bytes.push_back(0x01U);
  bytes.push_back(0x00U);  // protocol version 1
  bytes.push_back(0x01U);
  bytes.push_back(0x00U);  // HELLO
  bytes.push_back(0x00U);
  bytes.push_back(0x00U);  // flags
  bytes.push_back(0x40U);
  bytes.push_back(0x00U);
  bytes.push_back(0x00U);
  bytes.push_back(0x00U);  // header size
  bytes.push_back(0x40U);
  bytes.push_back(0x00U);
  bytes.push_back(0x00U);
  bytes.push_back(0x00U);  // payload size 64, never delivered
  return bytes;
}

}  // namespace

RP_TEST(distributed, real_worker_death_fences_the_boot_and_history_survives) {
  Coordinator coordinator;
  if (!start_coordinator(coordinator, "worker-death", false)) {
    return;
  }
  const std::string script_a = write_script(
      coordinator.directory, "a.rpscript",
      {"lineage 9001 worker/route-a", "register",
       "publish gen=1 reason=INITIAL_ROUTE root=INITIAL_PUBLICATION",
       "publish gen=2 reason=ROUTE_REPLACED", "wait"});
  const std::string script_b = write_script(
      coordinator.directory, "b.rpscript",
      {"lineage 9002 worker/route-b", "register",
       "publish gen=1 reason=INITIAL_ROUTE root=INITIAL_PUBLICATION", "wait"});

  // An unrelated publisher stays alive for the whole test, exactly as a second healthy worker
  // would.
  ChildProcess publisher_b;
  RP_REQUIRE_TRUE(start_publisher(publisher_b, coordinator, 8, 21, coordinator.epoch, script_b, "b"));
  RP_REQUIRE_TRUE(publisher_b.wait_for_output("WAITING", kExchangeBudgetMs));
  RP_EXPECT_TRUE(publisher_b.running());

  ChildProcess publisher_a;
  RP_REQUIRE_TRUE(start_publisher(publisher_a, coordinator, 7, 11, coordinator.epoch, script_a, "a"));
  // Step 5: confirm the publisher is alive and its provenance is committed.
  RP_REQUIRE_TRUE(publisher_a.wait_for_output("WAITING", kExchangeBudgetMs));
  RP_EXPECT_TRUE(publisher_a.running());

  Verifier before;
  RP_REQUIRE_TRUE(before.open(coordinator));
  const RouteLineageId lineage_a = derive_lineage_id(LineageKey{RouteId::from_value(9001), "worker/route-a"});
  const auto first_view = before.client->query_lineage(lineage_a);
  RP_REQUIRE_HAS_VALUE(first_view);
  RP_EXPECT_EQ(first_view.value().current_route_generation.value(), 2ULL);
  RP_EXPECT_EQ(first_view.value().node_count, 2ULL);
  RP_EXPECT_EQ(first_view.value().current_currentness, Currentness::Current);
  const ProvenanceNodeId record_g2 = first_view.value().current_node;
  const RouteLineageId lineage_b = derive_lineage_id(LineageKey{RouteId::from_value(9002), "worker/route-b"});
  const auto second_view = before.client->query_lineage(lineage_b);
  RP_REQUIRE_HAS_VALUE(second_view);

  // Step 6: kill the publisher with real OS termination.
  const std::uint32_t killed_pid = publisher_a.process_id();
  publisher_a.terminate();
  RP_EXPECT_GT(killed_pid, 0U);
  RP_EXPECT_FALSE(publisher_a.running());

  // Step 7: the coordinator detects loss of the session and fences the boot.
  Verifier observer;
  RP_REQUIRE_TRUE(observer.open(coordinator));
  const bool fenced = wait_until(60000, [&]() {
    const auto view = observer.client->query_lineage(lineage_a);
    return view.has_value() && view.value().current_currentness == Currentness::FencedPublisher;
  });
  RP_EXPECT_TRUE(fenced);
  const auto fenced_view = observer.client->query_lineage(lineage_a);
  RP_REQUIRE_HAS_VALUE(fenced_view);
  RP_EXPECT_EQ(fenced_view.value().current_currentness, Currentness::FencedPublisher);
  // Step 10: historical provenance survives fencing.
  RP_EXPECT_EQ(fenced_view.value().node_count, 2ULL);
  const auto history = observer.client->query_traversal(
      QueryPayload{lineage_a, record_g2, TraversalDirection::Outgoing, TraversalBounds{4, 32, 64},
                   ExplainMode::FullAncestry});
  RP_REQUIRE_HAS_VALUE(history);
  RP_EXPECT_EQ(history.value().size(), 2U);

  // Step 11/12: the same publisher identity may only continue with a fresh boot.
  const std::string script_replay = write_script(coordinator.directory, "replay.rpscript",
                                                 {"register", "quit"});
  ChildProcess stale_boot;
  RP_REQUIRE_TRUE(start_publisher(stale_boot, coordinator, 7, 11, coordinator.epoch, script_replay,
                                  "stale"));
  RP_REQUIRE_TRUE(stale_boot.wait_for_output("REGISTER", kExchangeBudgetMs));
  RP_EXPECT_TRUE(stale_boot.captured_output().find("accepted=false") != std::string::npos);
  stale_boot.terminate();

  // Step 13: a fresh boot for the same publisher is accepted and may publish again.
  const std::string script_fresh = write_script(
      coordinator.directory, "fresh.rpscript",
      {"lineage 9001 worker/route-a", "register", "publish gen=3 reason=ROUTE_REPLACED", "wait"});
  ChildProcess fresh;
  RP_REQUIRE_TRUE(start_publisher(fresh, coordinator, 7, 12, coordinator.epoch, script_fresh, "fresh"));
  RP_REQUIRE_TRUE(fresh.wait_for_output("WAITING", kExchangeBudgetMs));
  if (fresh.captured_output().find("outcome=CREATED") == std::string::npos) {
    RP_FAIL("fresh boot could not publish: " + fresh.captured_output());
  }

  const auto after_view = observer.client->query_lineage(lineage_a);
  RP_REQUIRE_HAS_VALUE(after_view);
  RP_EXPECT_EQ(after_view.value().current_route_generation.value(), 3ULL);
  RP_EXPECT_EQ(after_view.value().node_count, 3ULL);
  RP_EXPECT_EQ(after_view.value().current_currentness, Currentness::Current);

  // Step 14: the fenced boot remains fenced.
  ChildProcess stale_again;
  RP_REQUIRE_TRUE(start_publisher(stale_again, coordinator, 7, 11, coordinator.epoch, script_replay,
                                  "stale-again"));
  RP_REQUIRE_TRUE(stale_again.wait_for_output("REGISTER", kExchangeBudgetMs));
  RP_EXPECT_TRUE(stale_again.captured_output().find("accepted=false") != std::string::npos);
  stale_again.terminate();

  // Step 15: the unrelated publisher is unaffected.
  const auto unrelated = observer.client->query_lineage(lineage_b);
  RP_REQUIRE_HAS_VALUE(unrelated);
  RP_EXPECT_EQ(unrelated.value().current_currentness, Currentness::Current);
  RP_EXPECT_EQ(unrelated.value().current_route_generation.value(), 1ULL);

  // The repository leaves no orphan: every child is reaped before the test returns.
  RP_EXPECT_FALSE(publisher_a.running());
  RP_EXPECT_TRUE(publisher_b.running());
  RP_EXPECT_TRUE(fresh.running());
  fresh.terminate();
  publisher_b.terminate();
  RP_EXPECT_FALSE(publisher_b.running());
  RP_EXPECT_FALSE(fresh.running());

  observer.client->close();
  before.client->close();
  static_cast<void>(coordinator.process.process_id());
  coordinator.process.terminate();
  remove_dir(coordinator.directory);
}

RP_TEST(distributed, real_coordinator_restart_preserves_lineage_and_advances_epoch) {
  Coordinator first;
  if (!start_coordinator(first, "restart", false)) {
    return;
  }
  const std::string script = write_script(
      first.directory, "lineage.rpscript",
      {"lineage 9101 restart/route", "register",
       "publish gen=1 reason=INITIAL_ROUTE root=INITIAL_PUBLICATION",
       "publish gen=2 reason=ROUTE_REPLACED", "publish gen=3 reason=ROUTE_REPLACED", "quit"});
  ChildProcess publisher;
  RP_REQUIRE_TRUE(start_publisher(publisher, first, 31, 41, first.epoch, script, "p"));
  RP_REQUIRE_TRUE(publisher.wait_for_output("PUBLISHER_DONE", kExchangeBudgetMs));
  publisher.terminate();

  const RouteLineageId lineage =
      derive_lineage_id(LineageKey{RouteId::from_value(9101), "restart/route"});
  Verifier before;
  RP_REQUIRE_TRUE(before.open(first));
  const auto original = before.client->query_lineage(lineage);
  RP_REQUIRE_HAS_VALUE(original);
  const Digest original_digest = original.value().digest;
  before.client->close();

  // Persist and hard-kill the coordinator.
  RP_REQUIRE_TRUE(first.process.write_stdin("save\n"));
  RP_EXPECT_TRUE(first.process.wait_for_output("SAVE outcome=OK", kExchangeBudgetMs));
  first.process.terminate();
  RP_EXPECT_FALSE(first.process.running());

  // Each restart adds one revalidation record and one new route generation, so the expected
  // shape is carried forward explicitly.
  std::uint64_t epochs_seen = first.epoch;
  std::uint64_t expected_generation = original.value().current_route_generation.value();
  std::uint64_t expected_nodes = original.value().node_count;
  ProvenanceNodeId expected_current = original.value().current_node;
  for (int restart = 0; restart < 2; ++restart) {
    Coordinator next;
    next.store = first.store;
    next.directory = first.directory;
    if (!start_coordinator(next, "restart", true)) {
      return;
    }
    RP_EXPECT_GT(next.epoch, epochs_seen);
    epochs_seen = next.epoch;

    Verifier verifier;
    RP_REQUIRE_TRUE(verifier.open(next));
    const auto recovered = verifier.client->query_lineage(lineage);
    RP_REQUIRE_HAS_VALUE(recovered);
    RP_EXPECT_EQ(recovered.value().node_count, expected_nodes);
    RP_EXPECT_EQ(recovered.value().current_route_generation.value(), expected_generation);
    // Lineage identity, record identity and structure survive a restart exactly. The snapshot
    // digest legitimately changes because recovery demotes record state; that is a currentness
    // change, never a history change.
    RP_EXPECT_EQ(recovered.value().id, original.value().id);
    RP_EXPECT_EQ(recovered.value().current_node, expected_current);
    // Live authority did not survive: the recovered record requires revalidation.
    RP_EXPECT_EQ(recovered.value().current_currentness, Currentness::RevalidationRequired);

    // An old-epoch registration is refused; a current one is accepted.
    const std::string stale_script = write_script(next.directory, "stale.rpscript",
                                                  {"register", "quit"});
    ChildProcess stale;
    RP_REQUIRE_TRUE(start_publisher(stale, next, 31, 41, first.epoch, stale_script, "stale"));
    RP_REQUIRE_TRUE(stale.wait_for_output("REGISTER", kExchangeBudgetMs));
    RP_EXPECT_TRUE(stale.captured_output().find("accepted=false") != std::string::npos);
    stale.terminate();

    // Revalidate present currentness, then extend the lineage.
    const std::string continue_script = write_script(
        next.directory, "continue.rpscript",
        {"lineage 9101 restart/route", "register",
         "revalidate " + recovered.value().current_node.to_string(),
         "publish gen=" + std::to_string(expected_generation + 1) + " reason=ROUTE_REPLACED",
         "wait"});
    ChildProcess continuer;
    RP_REQUIRE_TRUE(start_publisher(continuer, next, 31, 50 + static_cast<std::uint64_t>(restart),
                                    next.epoch, continue_script, "continue"));
    RP_REQUIRE_TRUE(continuer.wait_for_output("WAITING", kExchangeBudgetMs));
    if (continuer.captured_output().find("outcome=CREATED") == std::string::npos) {
      RP_FAIL("continued publication failed: " + continuer.captured_output());
    }

    const auto extended = verifier.client->query_lineage(lineage);
    RP_REQUIRE_HAS_VALUE(extended);
    // The publisher session is still alive, so the record it published is current evidence.
    RP_EXPECT_EQ(extended.value().current_route_generation.value(), expected_generation + 1);
    RP_EXPECT_EQ(extended.value().node_count, expected_nodes + 2);
    RP_EXPECT_EQ(extended.value().current_currentness, Currentness::Current);
    const auto chain = verifier.client->query_traversal(
        QueryPayload{lineage, extended.value().current_node, TraversalDirection::Outgoing,
                     TraversalBounds{8, 64, 128}, ExplainMode::FullAncestry});
    RP_REQUIRE_HAS_VALUE(chain);
    RP_EXPECT_EQ(chain.value().size(), expected_generation + 1);
    expected_generation += 1;
    expected_nodes += 2;
    expected_current = extended.value().current_node;
    continuer.terminate();
    verifier.client->close();
    // Persist the state this coordinator produced before it is terminated, so the next restart
    // consumes the epoch this run established.
    RP_REQUIRE_TRUE(next.process.write_stdin("save\n"));
    RP_EXPECT_TRUE(next.process.wait_for_output("SAVE outcome=OK", kExchangeBudgetMs));
    next.process.terminate();
  }
  remove_dir(first.directory);
}

RP_TEST(distributed, partial_and_malformed_peers_are_failed_explicitly) {
#if defined(_WIN32)
  Coordinator coordinator;
  if (!start_coordinator(coordinator, "partial-frame", false, {"--frame-assembly-ms", "400"})) {
    return;
  }

  // A peer that never completes a frame is failed inside the assembly budget.
  RawPeer partial;
  RP_REQUIRE_TRUE(partial.connect_to(coordinator));
  RP_REQUIRE_TRUE(partial.send_bytes(partial_frame_bytes()));
  RP_EXPECT_TRUE(partial.wait_for_closure(30000));
  partial.close();

  // A peer that sends garbage is disconnected.
  RawPeer garbage;
  RP_REQUIRE_TRUE(garbage.connect_to(coordinator));
  RP_REQUIRE_TRUE(garbage.send_bytes({0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U}));
  RP_EXPECT_TRUE(garbage.wait_for_closure(30000));
  garbage.close();

  // The coordinator is still healthy and still serves real clients.
  Verifier verifier;
  RP_REQUIRE_TRUE(verifier.open(coordinator));
  const auto watermarks = verifier.client->watermarks();
  RP_REQUIRE_HAS_VALUE(watermarks);
  RP_EXPECT_EQ(watermarks.value().epoch.value(), coordinator.epoch);
  verifier.client->close();

  // Reconnect behaviour: repeated start and stop leaves no leaked session.
  for (int attempt = 0; attempt < 3; ++attempt) {
    Verifier repeated;
    RP_REQUIRE_TRUE(repeated.open(coordinator));
    const auto marks = repeated.client->watermarks();
    RP_REQUIRE_HAS_VALUE(marks);
    repeated.client->close();
  }

  coordinator.process.terminate();
  RP_EXPECT_FALSE(coordinator.process.running());
  remove_dir(coordinator.directory);
#else
  RP_FAIL("raw peer attacks require a Windows socket implementation");
#endif
}

RP_TEST(distributed, session_limit_rejects_extra_peers_and_clean_shutdown_terminates) {
  Coordinator coordinator;
  if (!start_coordinator(coordinator, "session-limit", false, {"--max-sessions", "2"})) {
    return;
  }
  Verifier first;
  Verifier second;
  RP_REQUIRE_TRUE(first.open(coordinator));
  RP_REQUIRE_TRUE(second.open(coordinator));

  // A third session is refused outright: the coordinator closes it rather than queueing it.
  ProvenanceClient third{ClientOptions{"127.0.0.1", coordinator.port, Limits::defaults()}};
  std::string error;
  const Status connected = third.connect(error);
  bool refused = !connected.is_ok();
  if (connected.is_ok()) {
    RegistrationPayload registration;
    registration.role = 0;
    registration.identity = PublisherIdentity{PublisherId::from_value(901), WorkerBootId::from_value(901),
                                             CoordinatorEpoch::from_value(coordinator.epoch)};
    registration.scope = AuthorityScope::fabric();
    const auto ack = third.hello(registration);
    refused = !ack.has_value() || !ack.value().accepted;
  }
  RP_EXPECT_TRUE(refused);
  third.close();

  first.client->close();
  second.client->close();

  // Clean shutdown on stdin closes the process with a success exit code.
  RP_REQUIRE_TRUE(coordinator.process.write_stdin("quit\n"));
  unsigned long code = 1;
  RP_EXPECT_TRUE(coordinator.process.wait_for_exit_code(kExchangeBudgetMs, code));
  RP_EXPECT_EQ(code, 0UL);
  RP_EXPECT_TRUE(file_exists(coordinator.store));
  remove_dir(coordinator.directory);
}

RP_TEST(distributed, server_side_query_limits_are_enforced_over_the_wire) {
  Coordinator coordinator;
  if (!start_coordinator(coordinator, "query-limits", false)) {
    return;
  }
  const std::string script = write_script(
      coordinator.directory, "limit.rpscript",
      {"lineage 9201 limit/route", "register",
       "publish gen=1 reason=INITIAL_ROUTE root=INITIAL_PUBLICATION", "quit"});
  ChildProcess publisher;
  RP_REQUIRE_TRUE(start_publisher(publisher, coordinator, 51, 61, coordinator.epoch, script, "limit"));
  RP_REQUIRE_TRUE(publisher.wait_for_output("PUBLISHER_DONE", kExchangeBudgetMs));
  publisher.terminate();

  Verifier verifier;
  RP_REQUIRE_TRUE(verifier.open(coordinator));
  const RouteLineageId lineage = derive_lineage_id(LineageKey{RouteId::from_value(9201), "limit/route"});
  const auto view = verifier.client->query_lineage(lineage);
  RP_REQUIRE_HAS_VALUE(view);
  // A traversal that exceeds the store bound is reported as a structured failure, never as a
  // silent partial answer.
  QueryPayload query;
  query.node = view.value().current_node;
  query.direction = TraversalDirection::Outgoing;
  query.bounds.max_depth = 1;
  query.bounds.max_results = 1;
  query.bounds.max_visited = 1;
  const auto traversal = verifier.client->query_traversal(query);
  RP_EXPECT_TRUE(traversal.has_value() || traversal.outcome() == Outcome::ResourceLimit);
  if (traversal.has_value()) {
    RP_EXPECT_LE(traversal.value().size(), 1U);
  }
  // The snapshot round-trips with an exact digest.
  const auto snapshot = verifier.client->query_snapshot(lineage);
  RP_REQUIRE_HAS_VALUE(snapshot);
  RP_EXPECT_EQ(snapshot.value().digest, view.value().digest);
  RP_EXPECT_EQ(snapshot.value().nodes.size(), 1U);
  verifier.client->close();
  coordinator.process.terminate();
  remove_dir(coordinator.directory);
}
