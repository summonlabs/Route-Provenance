// Route Provenance coordinator process.
//
// Hosts one ProvenanceStore, owns publication authority for it and serves publisher and query
// sessions over a loopback transport. This is a single-coordinator authority model: it is not
// a consensus protocol and makes no split-brain claim.
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "route_provenance/runtime.hpp"
#include "route_provenance/version.hpp"

namespace {

using route_provenance::AuthorityContext;
using route_provenance::AuthorityScope;
using route_provenance::CoordinatorEpoch;
using route_provenance::DependencyWatermarks;
using route_provenance::Limits;
using route_provenance::MutationAttemptId;
using route_provenance::ProvenanceServer;
using route_provenance::ProvenanceStore;
using route_provenance::PublisherId;
using route_provenance::PublisherIdentity;
using route_provenance::PublisherRecord;
using route_provenance::ServerOptions;
using route_provenance::Status;
using route_provenance::StoreStats;
using route_provenance::WorkerBootId;

struct Options {
  std::string store_path;
  std::string ready_file;
  std::uint16_t port = 0;
  CoordinatorEpoch epoch = CoordinatorEpoch::from_value(1);
  PublisherId publisher = PublisherId::from_value(1);
  WorkerBootId boot = WorkerBootId::from_value(1);
  bool load_existing = false;
  bool save_on_exit = true;
  Limits limits;
};

[[nodiscard]] bool parse_u64(const std::string& text, std::uint64_t& out) {
  const std::optional<std::uint64_t> value = [&]() -> std::optional<std::uint64_t> {
    if (text.empty() || text.size() > 20) {
      return std::nullopt;
    }
    std::uint64_t result = 0;
    for (const char ch : text) {
      if (ch < '0' || ch > '9') {
        return std::nullopt;
      }
      result = result * 10U + static_cast<std::uint64_t>(ch - '0');
    }
    return result;
  }();
  if (!value.has_value()) {
    return false;
  }
  out = *value;
  return true;
}

void usage() {
  std::cout << "usage: rp_coordinator --store <path> [--port N] [--epoch N] [--publisher N] "
               "[--boot N]\n"
               "                      [--load] [--ready-file <path>] [--no-save-on-exit]\n"
               "                      [--max-sessions N] [--max-frame-bytes N] "
               "[--frame-assembly-ms N]\n"
               "Commands on stdin: save | epoch <n> | stats | quit\n";
}

}  // namespace

int main(int argc, char** argv) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    const auto next = [&](std::string& target) {
      if (i + 1 < argc) {
        target = argv[++i];
      }
    };
    std::string value;
    if (arg == "--store") {
      next(options.store_path);
    } else if (arg == "--ready-file") {
      next(options.ready_file);
    } else if (arg == "--port") {
      next(value);
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed) || parsed > 65535U) {
        std::cerr << "invalid --port\n";
        return 2;
      }
      options.port = static_cast<std::uint16_t>(parsed);
    } else if (arg == "--epoch") {
      next(value);
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed) || parsed == 0) {
        std::cerr << "invalid --epoch\n";
        return 2;
      }
      options.epoch = CoordinatorEpoch::from_value(parsed);
    } else if (arg == "--publisher") {
      next(value);
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed) || parsed == 0) {
        std::cerr << "invalid --publisher\n";
        return 2;
      }
      options.publisher = PublisherId::from_value(parsed);
    } else if (arg == "--boot") {
      next(value);
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed) || parsed == 0) {
        std::cerr << "invalid --boot\n";
        return 2;
      }
      options.boot = WorkerBootId::from_value(parsed);
    } else if (arg == "--max-sessions") {
      next(value);
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed) || parsed == 0) {
        std::cerr << "invalid --max-sessions\n";
        return 2;
      }
      options.limits.max_sessions = static_cast<std::uint32_t>(parsed);
    } else if (arg == "--max-frame-bytes") {
      next(value);
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed) || parsed == 0) {
        std::cerr << "invalid --max-frame-bytes\n";
        return 2;
      }
      options.limits.max_frame_bytes = static_cast<std::uint32_t>(parsed);
    } else if (arg == "--frame-assembly-ms") {
      next(value);
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed) || parsed == 0) {
        std::cerr << "invalid --frame-assembly-ms\n";
        return 2;
      }
      options.limits.max_frame_assembly_ms = static_cast<std::uint32_t>(parsed);
    } else if (arg == "--load") {
      options.load_existing = true;
    } else if (arg == "--no-save-on-exit") {
      options.save_on_exit = false;
    } else if (arg == "--help" || arg == "-h") {
      usage();
      return 0;
    } else {
      std::cerr << "unknown argument: " << arg << "\n";
      usage();
      return 2;
    }
  }
  if (options.store_path.empty()) {
    std::cerr << "missing --store\n";
    usage();
    return 2;
  }

  route_provenance::ProvenanceStore store(options.limits);
  bool loaded = false;
  if (options.load_existing) {
    const route_provenance::Status status = store.load(options.store_path);
    if (route_provenance::outcome_is_rejection(status.outcome())) {
      std::cerr << "load failed: " << route_provenance::to_string(status.outcome()) << " "
                << status.detail() << "\n";
      return 3;
    }
    loaded = true;
    const route_provenance::Result<route_provenance::DependencyWatermarks> marks = store.watermarks();
    if (marks.has_value() && marks.value().epoch.valid()) {
      const std::optional<CoordinatorEpoch> next = marks.value().epoch.try_next();
      if (!next.has_value()) {
        std::cerr << "coordinator epoch exhausted\n";
        return 3;
      }
      options.epoch = *next;
    }
  }

  const route_provenance::CoordinatorEpoch epoch = options.epoch;
  const route_provenance::PublisherIdentity identity{options.publisher, options.boot, epoch};
  const route_provenance::AuthorityScope fabric = route_provenance::AuthorityScope::fabric();
  const route_provenance::Result<route_provenance::PublisherRecord> registered =
      store.register_publisher(identity, fabric);
  if (!registered.has_value()) {
    std::cerr << "coordinator registration failed: "
              << route_provenance::to_string(registered.outcome()) << " " << registered.detail() << "\n";
    return 3;
  }
  route_provenance::AuthorityContext authority;
  authority.publisher = identity;
  authority.scope = fabric;
  authority.attempt = route_provenance::MutationAttemptId::from_value(1);

  route_provenance::ServerOptions server_options;
  server_options.port = options.port;
  server_options.limits = options.limits;
  server_options.client_scope = fabric;
  server_options.coordinator_authority = authority;
  route_provenance::ProvenanceServer server(store, server_options);
  std::string error;
  const route_provenance::Status started = server.start(error);
  if (!started.is_ok()) {
    std::cerr << "start failed: " << error << "\n";
    return 3;
  }

  if (!options.ready_file.empty()) {
    std::ofstream ready(options.ready_file, std::ios::binary | std::ios::trunc);
    ready << "port=" << server.port() << "\n";
    ready << "epoch=" << epoch.to_string() << "\n";
    ready << "store=" << options.store_path << "\n";
    ready << "loaded=" << (loaded ? "true" : "false") << "\n";
    ready.flush();
  }
  std::cout << "COORDINATOR READY port=" << server.port() << " epoch=" << epoch.to_string()
            << " loaded=" << (loaded ? "true" : "false") << "\n";
  std::cout.flush();

  std::string line;
  while (std::getline(std::cin, line)) {
    if (line == "save") {
      const route_provenance::Status saved = store.save(options.store_path);
      std::cout << "SAVE outcome=" << route_provenance::to_string(saved.outcome())
                << " detail=" << saved.detail() << "\n";
      std::cout.flush();
    } else if (line == "stats") {
      const route_provenance::Result<route_provenance::StoreStats> stats = store.stats();
      if (stats.has_value()) {
        const route_provenance::ServerStats server_stats = server.stats();
        std::cout << "STATS lineages=" << stats.value().lineage_count
                  << " nodes=" << stats.value().node_count << " edges=" << stats.value().edge_count
                  << " active_sessions=" << server_stats.active_sessions
                  << " sessions_accepted=" << server_stats.sessions_accepted
                  << " sessions_closed=" << server_stats.sessions_closed
                  << " publishers_fenced=" << server_stats.publishers_fenced
                  << " protocol_failures=" << server_stats.protocol_failures << "\n";
      } else {
        std::cout << "STATS outcome=" << route_provenance::to_string(stats.outcome()) << "\n";
      }
      std::cout.flush();
    } else if (line.rfind("epoch ", 0) == 0) {
      std::uint64_t parsed = 0;
      if (parse_u64(line.substr(6), parsed) && parsed != 0) {
        const route_provenance::Status advanced =
            server.advance_epoch(route_provenance::CoordinatorEpoch::from_value(parsed));
        std::cout << "EPOCH outcome=" << route_provenance::to_string(advanced.outcome())
                  << " value=" << parsed << "\n";
      } else {
        std::cout << "EPOCH outcome=MALFORMED_REQUEST\n";
      }
      std::cout.flush();
    } else if (line == "quit" || line.empty()) {
      break;
    }
  }

  static_cast<void>(server.stop());
  if (options.save_on_exit) {
    const route_provenance::Status saved = store.save(options.store_path);
    std::cout << "SHUTDOWN SAVE outcome=" << route_provenance::to_string(saved.outcome()) << "\n";
  } else {
    std::cout << "SHUTDOWN\n";
  }
  std::cout.flush();
  return 0;
}
