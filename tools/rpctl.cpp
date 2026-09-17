// Route Provenance command line interface.
//
// Output is deterministic and script friendly: one key=value record per line, no timestamps.
// Read-only commands work offline against a store file. Mutation commands require a live
// coordinator session, because publication authority is not a local privilege.
#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "route_provenance/persistence.hpp"
#include "route_provenance/runtime.hpp"
#include "route_provenance/store.hpp"
#include "route_provenance/version.hpp"

namespace {

using route_provenance::Outcome;
using route_provenance::ProvenanceStore;
using route_provenance::Status;

struct Arguments {
  std::string command;
  std::string subcommand;
  std::string store;
  std::string store_b;
  std::string connect;
  std::string key;
  std::string mode = "FULL_ANCESTRY";
  std::uint64_t lineage = 0;
  std::uint64_t node = 0;
  std::uint64_t route = 0;
  std::uint64_t publisher = 0;
  std::uint64_t boot = 0;
  std::uint64_t epoch = 0;
  std::uint64_t target = 0;
  std::uint32_t depth = 0;
  std::uint32_t limit = 0;
};

[[nodiscard]] bool parse_u64(const std::string& text, std::uint64_t& out) {
  if (text.empty() || text.size() > 19) {
    return false;
  }
  std::uint64_t result = 0;
  for (const char ch : text) {
    if (ch < '0' || ch > '9') {
      return false;
    }
    result = result * 10U + static_cast<std::uint64_t>(ch - '0');
  }
  out = result;
  return true;
}

void usage() {
  std::cout << "Route Provenance " << route_provenance::kVersionString << "\n"
            << "usage: rpctl <command> [options]\n"
            << "commands:\n"
            << "  version\n"
            << "  store inspect     --store <path>\n"
            << "  lineage list      (--store <path> | --connect <ip:port>)\n"
            << "  lineage show      --lineage <id> (--store | --connect)\n"
            << "  provenance show   --node <id> (--store | --connect)\n"
            << "  ancestry          --node <id> [--depth N] (--store | --connect)\n"
            << "  descendants       --node <id> [--depth N] (--store | --connect)\n"
            << "  cause             --node <id> [--mode MODE] (--store | --connect)\n"
            << "  snapshot          --lineage <id> (--store | --connect)\n"
            << "  diff              --store <a> --store-b <b> --lineage <id>\n"
            << "  supersede         --connect <ip:port> --publisher N --boot N --epoch N\n"
            << "                    --route N --key <text> --target <node> --reason CODE\n"
            << "  withdraw | revoke | retire | revalidate | invalidate | correct\n"
            << "                    --connect ... --target <node>\n"
            << "  link              --connect ... --target <from> --node <to> --edge TYPE\n";
}

[[nodiscard]] Status load_store(const Arguments& arguments, ProvenanceStore& store) {
  const Status loaded = store.load(arguments.store);
  return loaded;
}

void print_publication(const std::string& label, const route_provenance::Result<route_provenance::Publication>& result) {
  std::cout << label << " outcome=" << route_provenance::to_string(result.outcome());
  if (result.has_value()) {
    std::cout << " lineage=" << result.value().lineage.to_string()
              << " node=" << result.value().node.to_string()
              << " lineage_generation=" << result.value().lineage_generation.to_string()
              << " store_generation=" << result.value().store_generation.to_string()
              << " lifecycle=" << route_provenance::to_string(result.value().lifecycle)
              << " currentness=" << route_provenance::to_string(result.value().currentness);
  }
  if (!result.detail().empty()) {
    std::cout << " detail=" << result.detail();
  }
  std::cout << "\n";
}

void print_nodes(const std::vector<route_provenance::ProvenanceNode>& nodes) {
  std::vector<route_provenance::ProvenanceNode> ordered = nodes;
  std::sort(ordered.begin(), ordered.end(),
            [](const route_provenance::ProvenanceNode& left,
               const route_provenance::ProvenanceNode& right) { return left.id < right.id; });
  for (const route_provenance::ProvenanceNode& node : ordered) {
    std::cout << "node id=" << node.id.to_string()
              << " kind=" << route_provenance::to_string(node.kind)
              << " generation=" << node.route_generation.to_string()
              << " reason=" << route_provenance::to_string(node.reason)
              << " source=" << route_provenance::to_string(node.source)
              << " lifecycle=" << route_provenance::to_string(node.lifecycle)
              << " currentness=" << route_provenance::to_string(node.currentness)
              << " historically_valid=" << (route_provenance::node_is_historically_valid(node) ? "true" : "false")
              << " digest=" << node.digest().hex() << "\n";
  }
  std::cout << "count=" << ordered.size() << "\n";
}

}  // namespace

int main(int argc, char** argv) {
  Arguments arguments;
  std::vector<std::string> positional;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    const auto next = [&](std::string& target) {
      if (i + 1 < argc) {
        target = argv[++i];
      }
    };
    std::string value;
    if (arg == "--store") {
      next(arguments.store);
    } else if (arg == "--store-b") {
      next(arguments.store_b);
    } else if (arg == "--connect") {
      next(arguments.connect);
    } else if (arg == "--key") {
      next(arguments.key);
    } else if (arg == "--mode") {
      next(arguments.mode);
    } else if (arg == "--edge") {
      next(value);
      arguments.mode = value;
    } else if (arg == "--lineage") {
      next(value);
      static_cast<void>(parse_u64(value, arguments.lineage));
    } else if (arg == "--node") {
      next(value);
      static_cast<void>(parse_u64(value, arguments.node));
    } else if (arg == "--route") {
      next(value);
      static_cast<void>(parse_u64(value, arguments.route));
    } else if (arg == "--publisher") {
      next(value);
      static_cast<void>(parse_u64(value, arguments.publisher));
    } else if (arg == "--boot") {
      next(value);
      static_cast<void>(parse_u64(value, arguments.boot));
    } else if (arg == "--epoch") {
      next(value);
      static_cast<void>(parse_u64(value, arguments.epoch));
    } else if (arg == "--target") {
      next(value);
      static_cast<void>(parse_u64(value, arguments.target));
    } else if (arg == "--reason") {
      next(arguments.key.empty() ? arguments.mode : arguments.mode);
      next(value);
    } else if (arg == "--depth") {
      next(value);
      std::uint64_t parsed = 0;
      static_cast<void>(parse_u64(value, parsed));
      arguments.depth = static_cast<std::uint32_t>(parsed);
    } else if (arg == "--limit") {
      next(value);
      std::uint64_t parsed = 0;
      static_cast<void>(parse_u64(value, parsed));
      arguments.limit = static_cast<std::uint32_t>(parsed);
    } else if (arg == "--help" || arg == "-h") {
      usage();
      return 0;
    } else if (arg.rfind("--", 0) == 0) {
      std::cout << "unknown_option=" << arg << "\n";
      return 2;
    } else {
      positional.push_back(arg);
    }
  }
  if (positional.size() > 2) {
    usage();
    return 2;
  }
  if (!positional.empty()) {
    arguments.command = positional[0];
  }
  if (positional.size() > 1) {
    arguments.subcommand = positional[1];
  }

  if (arguments.command == "version" || arguments.command.empty()) {
    std::cout << route_provenance::version_report();
    return 0;
  }

  if (arguments.command == "store" && arguments.subcommand == "inspect") {
    if (arguments.store.empty()) {
      std::cout << "outcome=MALFORMED_REQUEST detail=--store is required\n";
      return 2;
    }
    route_provenance::Limits limits;
    const route_provenance::Result<route_provenance::StoreImage> image =
        route_provenance::read_store_image(arguments.store, limits);
    if (!image.has_value()) {
      std::cout << "outcome=" << route_provenance::to_string(image.outcome())
                << " detail=" << image.detail() << "\n";
      return 3;
    }
    std::cout << "store lineages=" << image.value().lineages.size()
              << " nodes=" << image.value().node_count()
              << " edges=" << image.value().edge_count()
              << " store_generation=" << image.value().watermarks.store_generation.to_string()
              << " epoch=" << image.value().watermarks.epoch.to_string()
              << " path_authority_generation=" << image.value().watermarks.path_authority_generation.to_string()
              << " policy_generation=" << image.value().watermarks.policy_generation.to_string()
              << " evidence_generation=" << image.value().watermarks.evidence_generation.to_string()
              << " plan_generation=" << image.value().watermarks.plan_generation.to_string() << "\n";
    for (const route_provenance::StoredLineage& lineage : image.value().lineages) {
      std::cout << "lineage id=" << lineage.state.id.to_string()
                << " route=" << lineage.state.key.route.to_string()
                << " key=" << lineage.state.key.semantic_key
                << " lifecycle=" << route_provenance::to_string(lineage.state.lifecycle)
                << " current_generation=" << lineage.state.current_route_generation.to_string()
                << " current_node=" << lineage.state.current_node.to_string()
                << " nodes=" << lineage.nodes.size()
                << " edges=" << lineage.edges.size()
                << " lineage_generation=" << lineage.state.lineage_generation.to_string() << "\n";
    }
    return 0;
  }

  // Online commands: queries and mutations against a live coordinator.
  if (!arguments.connect.empty()) {
    const std::size_t separator = arguments.connect.find(':');
    if (separator == std::string::npos) {
      std::cout << "outcome=MALFORMED_REQUEST detail=--connect must be ip:port\n";
      return 2;
    }
    route_provenance::ClientOptions client_options;
    client_options.address = arguments.connect.substr(0, separator);
    std::uint64_t port = 0;
    if (!parse_u64(arguments.connect.substr(separator + 1), port) || port == 0 || port > 65535U) {
      std::cout << "outcome=MALFORMED_REQUEST detail=invalid port\n";
      return 2;
    }
    client_options.port = static_cast<std::uint16_t>(port);
    route_provenance::ProvenanceClient client(client_options);
    std::string error;
    const Status connected = client.connect(error);
    if (!connected.is_ok()) {
      std::cout << "outcome=" << route_provenance::to_string(connected.outcome())
                << " detail=" << error << "\n";
      return 3;
    }
    const route_provenance::PublisherId publisher = route_provenance::PublisherId::from_value(
        arguments.publisher == 0 ? 100 : arguments.publisher);
    const route_provenance::WorkerBootId boot = route_provenance::WorkerBootId::from_value(
        arguments.boot == 0 ? 1 : arguments.boot);
    const route_provenance::CoordinatorEpoch epoch = route_provenance::CoordinatorEpoch::from_value(
        arguments.epoch == 0 ? 1 : arguments.epoch);
    route_provenance::RegistrationPayload registration;
    registration.role = 0;
    registration.identity = route_provenance::PublisherIdentity{publisher, boot, epoch};
    registration.scope = route_provenance::AuthorityScope::fabric();
    const route_provenance::Result<route_provenance::HelloAckPayload> ack = client.hello(registration);
    if (!ack.has_value() || !ack.value().accepted) {
      std::cout << "outcome=" << route_provenance::to_string(ack.outcome())
                << " detail=" << (ack.has_value() ? ack.value().detail : ack.detail()) << "\n";
      return 3;
    }

    const auto context = [&]() {
      route_provenance::AuthorityContext authority;
      authority.publisher = registration.identity;
      authority.scope = route_provenance::AuthorityScope::fabric();
      authority.attempt = route_provenance::MutationAttemptId::from_value(
          (arguments.node == 0 ? 1 : arguments.node) * 100ULL + (arguments.target % 100ULL));
      return authority;
    };

    if (arguments.command == "lineage" && arguments.subcommand == "list") {
      std::cout << "outcome=OK detail=online lineage listing is bounded by the coordinator query limit\n";
      return 0;
    }
    if (arguments.command == "lineage" && arguments.subcommand == "show") {
      const route_provenance::Result<route_provenance::LineageView> view =
          client.query_lineage(route_provenance::RouteLineageId::from_value(arguments.lineage));
      if (!view.has_value()) {
        std::cout << "outcome=" << route_provenance::to_string(view.outcome())
                  << " detail=" << view.detail() << "\n";
        return 3;
      }
      std::cout << "lineage id=" << view.value().id.to_string()
                << " route=" << view.value().key.route.to_string()
                << " key=" << view.value().key.semantic_key
                << " lifecycle=" << route_provenance::to_string(view.value().lifecycle)
                << " current_generation=" << view.value().current_route_generation.to_string()
                << " current_node=" << view.value().current_node.to_string()
                << " currentness=" << route_provenance::to_string(view.value().current_currentness)
                << " nodes=" << view.value().node_count
                << " edges=" << view.value().edge_count
                << " lineage_generation=" << view.value().lineage_generation.to_string()
                << " digest=" << view.value().digest.hex() << "\n";
      return 0;
    }
    if (arguments.command == "provenance" && arguments.subcommand == "show") {
      route_provenance::QueryPayload query;
      query.node = route_provenance::ProvenanceNodeId::from_value(arguments.node);
      const route_provenance::Result<std::vector<route_provenance::ProvenanceNode>> nodes =
          client.query_traversal(query);
      if (!nodes.has_value()) {
        std::cout << "outcome=" << route_provenance::to_string(nodes.outcome())
                  << " detail=" << nodes.detail() << "\n";
        return 3;
      }
      print_nodes(nodes.value());
      return 0;
    }
    if (arguments.command == "ancestry" || arguments.command == "descendants") {
      route_provenance::QueryPayload query;
      query.node = route_provenance::ProvenanceNodeId::from_value(arguments.node);
      query.direction = arguments.command == "ancestry" ? route_provenance::TraversalDirection::Outgoing
                                                        : route_provenance::TraversalDirection::Incoming;
      query.bounds.max_depth = arguments.depth;
      query.bounds.max_results = arguments.limit;
      const route_provenance::Result<std::vector<route_provenance::ProvenanceNode>> nodes =
          client.query_traversal(query);
      if (!nodes.has_value()) {
        std::cout << "outcome=" << route_provenance::to_string(nodes.outcome())
                  << " detail=" << nodes.detail() << "\n";
        return 3;
      }
      print_nodes(nodes.value());
      return 0;
    }
    if (arguments.command == "cause") {
      route_provenance::QueryPayload query;
      query.node = route_provenance::ProvenanceNodeId::from_value(arguments.node);
      const std::optional<route_provenance::ExplainMode> mode =
          route_provenance::parse_explain_mode(arguments.mode);
      query.mode = mode.value_or(route_provenance::ExplainMode::FullAncestry);
      const route_provenance::Result<route_provenance::Explanation> explanation = client.query_cause(query);
      if (!explanation.has_value()) {
        std::cout << "outcome=" << route_provenance::to_string(explanation.outcome())
                  << " detail=" << explanation.detail() << "\n";
        return 3;
      }
      std::cout << route_provenance::render_explanation(explanation.value());
      return 0;
    }
    if (arguments.command == "snapshot") {
      const route_provenance::Result<route_provenance::Snapshot> snapshot =
          client.query_snapshot(route_provenance::RouteLineageId::from_value(arguments.lineage));
      if (!snapshot.has_value()) {
        std::cout << "outcome=" << route_provenance::to_string(snapshot.outcome())
                  << " detail=" << snapshot.detail() << "\n";
        return 3;
      }
      std::cout << "snapshot id=" << snapshot.value().id.to_string()
                << " lineage=" << snapshot.value().lineage.to_string()
                << " current_generation=" << snapshot.value().current_route_generation.to_string()
                << " currentness=" << route_provenance::to_string(snapshot.value().current_currentness)
                << " nodes=" << snapshot.value().nodes.size()
                << " edges=" << snapshot.value().edges.size()
                << " digest=" << snapshot.value().digest.hex() << "\n";
      print_nodes(snapshot.value().nodes);
      return 0;
    }

    const std::string key = arguments.key;
    const route_provenance::LineageKey lineage_key{route_provenance::RouteId::from_value(arguments.route), key};
    if (arguments.command == "supersede" || arguments.command == "replace") {
      route_provenance::PublicationPayload payload;
      payload.key = lineage_key;
      payload.route_generation = route_provenance::RouteGeneration::from_value(arguments.lineage);
      payload.reason = route_provenance::parse_reason_code(arguments.mode)
                           .value_or(route_provenance::ReasonCode::RouteReplaced);
      payload.source = route_provenance::SourceClass::Administrative;
      payload.route_state_digest = route_provenance::Digest::hash("cli:supersede:" + key);
      payload.authority = context();
      if (arguments.target != 0) {
        route_provenance::EdgeSpec edge;
        edge.type = route_provenance::EdgeType::Supersedes;
        edge.target = route_provenance::ProvenanceNodeId::from_value(arguments.target);
        edge.reason = payload.reason;
        edge.source = payload.source;
        payload.edges.push_back(edge);
      }
      const route_provenance::Result<route_provenance::Publication> result = client.publish(payload);
      print_publication("supersede", result);
      return result.has_value() ? 0 : 3;
    }
    if (arguments.command == "withdraw" || arguments.command == "revoke" ||
        arguments.command == "retire" || arguments.command == "revalidate" ||
        arguments.command == "invalidate") {
      route_provenance::AdministrativePayload payload;
      payload.key = lineage_key;
      payload.target = route_provenance::ProvenanceNodeId::from_value(arguments.target);
      payload.source = route_provenance::SourceClass::Administrative;
      payload.authority = context();
      payload.allow_non_current_target = true;
      route_provenance::MessageId message = route_provenance::MessageId::Withdraw;
      if (arguments.command == "withdraw") {
        message = route_provenance::MessageId::Withdraw;
        payload.reason = route_provenance::ReasonCode::AdminWithdrawal;
      } else if (arguments.command == "revoke") {
        message = route_provenance::MessageId::Revoke;
        payload.reason = route_provenance::ReasonCode::Revocation;
      } else if (arguments.command == "retire") {
        message = route_provenance::MessageId::Retire;
        payload.reason = route_provenance::ReasonCode::Retirement;
      } else if (arguments.command == "revalidate") {
        message = route_provenance::MessageId::Revalidate;
        payload.reason = route_provenance::ReasonCode::RecoveryRevalidation;
      } else {
        message = route_provenance::MessageId::Invalidate;
        payload.reason = route_provenance::ReasonCode::Invalidation;
      }
      const route_provenance::Result<route_provenance::Publication> result =
          client.administrative(message, payload);
      print_publication(arguments.command, result);
      return result.has_value() ? 0 : 3;
    }
    if (arguments.command == "correct") {
      route_provenance::CorrectionPayload payload;
      payload.key = lineage_key;
      payload.target = route_provenance::ProvenanceNodeId::from_value(arguments.target);
      payload.source = route_provenance::SourceClass::Administrative;
      payload.authority = context();
      const route_provenance::Result<route_provenance::Publication> result = client.correct(payload);
      print_publication("correct", result);
      return result.has_value() ? 0 : 3;
    }
    if (arguments.command == "link") {
      route_provenance::LinkPayload payload;
      payload.key = lineage_key;
      payload.type = route_provenance::parse_edge_type(arguments.mode)
                         .value_or(route_provenance::EdgeType::AuthorizedBy);
      payload.from = route_provenance::ProvenanceNodeId::from_value(arguments.target);
      payload.to = route_provenance::ProvenanceNodeId::from_value(arguments.node);
      payload.source = route_provenance::SourceClass::Administrative;
      payload.authority = context();
      const route_provenance::Result<route_provenance::Publication> result = client.link(payload);
      print_publication("link", result);
      return result.has_value() ? 0 : 3;
    }
    std::cout << "outcome=MALFORMED_REQUEST detail=unknown online command\n";
    return 2;
  }

  // Offline commands operate on a store file through the recovery path: currentness reflects
  // post-restart reality, and history is preserved exactly.
  if (arguments.store.empty()) {
    usage();
    return 2;
  }
  route_provenance::Limits limits;
  ProvenanceStore store(limits);
  const Status loaded = load_store(arguments, store);
  if (route_provenance::outcome_is_rejection(loaded.outcome())) {
    std::cout << "outcome=" << route_provenance::to_string(loaded.outcome())
              << " detail=" << loaded.detail() << "\n";
    return 3;
  }
  if (arguments.command == "diff") {
    ProvenanceStore other(limits);
    const Status other_loaded = other.load(arguments.store_b);
    if (route_provenance::outcome_is_rejection(other_loaded.outcome())) {
      std::cout << "outcome=" << route_provenance::to_string(other_loaded.outcome())
                << " detail=" << other_loaded.detail() << "\n";
      return 3;
    }
    const route_provenance::Result<route_provenance::Snapshot> before =
        store.snapshot(route_provenance::RouteLineageId::from_value(arguments.lineage));
    const route_provenance::Result<route_provenance::Snapshot> after =
        other.snapshot(route_provenance::RouteLineageId::from_value(arguments.lineage));
    if (!before.has_value() || !after.has_value()) {
      std::cout << "outcome=NODE_NOT_FOUND detail=snapshot unavailable\n";
      return 3;
    }
    const route_provenance::Result<route_provenance::Diff> diff = store.diff(before.value(), after.value());
    if (!diff.has_value()) {
      std::cout << "outcome=" << route_provenance::to_string(diff.outcome())
                << " detail=" << diff.detail() << "\n";
      return 3;
    }
    for (const route_provenance::DiffEntry& entry : diff.value().entries) {
      std::cout << "diff kind=" << route_provenance::to_string(entry.kind)
                << " node=" << entry.node.to_string()
                << " edge=" << entry.edge.to_string()
                << " currentness=" << route_provenance::to_string(entry.before_currentness) << "->"
                << route_provenance::to_string(entry.after_currentness)
                << " lifecycle=" << route_provenance::to_string(entry.before_lifecycle) << "->"
                << route_provenance::to_string(entry.after_lifecycle)
                << " detail=" << entry.detail << "\n";
    }
    std::cout << "diff_count=" << diff.value().entries.size()
              << " digest=" << diff.value().digest.hex() << "\n";
    return 0;
  }
  if (arguments.command == "lineage" && (arguments.subcommand == "list" || arguments.subcommand.empty())) {
    const route_provenance::Result<std::vector<route_provenance::LineageView>> lineages = store.list_lineages();
    if (!lineages.has_value()) {
      std::cout << "outcome=" << route_provenance::to_string(lineages.outcome())
                << " detail=" << lineages.detail() << "\n";
      return 3;
    }
    for (const route_provenance::LineageView& view : lineages.value()) {
      std::cout << "lineage id=" << view.id.to_string()
                << " route=" << view.key.route.to_string()
                << " key=" << view.key.semantic_key
                << " lifecycle=" << route_provenance::to_string(view.lifecycle)
                << " current_generation=" << view.current_route_generation.to_string()
                << " current_node=" << view.current_node.to_string()
                << " currentness=" << route_provenance::to_string(view.current_currentness)
                << " nodes=" << view.node_count
                << " edges=" << view.edge_count
                << " lineage_generation=" << view.lineage_generation.to_string()
                << " digest=" << view.digest.hex() << "\n";
    }
    std::cout << "lineage_count=" << lineages.value().size() << "\n";
    return 0;
  }
  if (arguments.command == "lineage" && arguments.subcommand == "show") {
    const route_provenance::Result<route_provenance::LineageView> view =
        store.lineage(route_provenance::RouteLineageId::from_value(arguments.lineage));
    if (!view.has_value()) {
      std::cout << "outcome=" << route_provenance::to_string(view.outcome())
                << " detail=" << view.detail() << "\n";
      return 3;
    }
    std::cout << "lineage id=" << view.value().id.to_string()
              << " route=" << view.value().key.route.to_string()
              << " key=" << view.value().key.semantic_key
              << " lifecycle=" << route_provenance::to_string(view.value().lifecycle)
              << " current_generation=" << view.value().current_route_generation.to_string()
              << " current_node=" << view.value().current_node.to_string()
              << " currentness=" << route_provenance::to_string(view.value().current_currentness)
              << " nodes=" << view.value().node_count
              << " edges=" << view.value().edge_count
              << " lineage_generation=" << view.value().lineage_generation.to_string()
              << " digest=" << view.value().digest.hex() << "\n";
    return 0;
  }
  if (arguments.command == "provenance" && arguments.subcommand == "show") {
    const route_provenance::Result<route_provenance::ProvenanceNode> node =
        store.node(route_provenance::ProvenanceNodeId::from_value(arguments.node));
    if (!node.has_value()) {
      std::cout << "outcome=" << route_provenance::to_string(node.outcome())
                << " detail=" << node.detail() << "\n";
      return 3;
    }
    print_nodes({node.value()});
    const route_provenance::Result<std::vector<route_provenance::ProvenanceEdge>> parents =
        store.parents(node.value().id);
    if (parents.has_value()) {
      for (const route_provenance::ProvenanceEdge& edge : parents.value()) {
        std::cout << "edge id=" << edge.id.to_string()
                  << " derivation=" << edge.derivation.to_string()
                  << " type=" << route_provenance::to_string(edge.type)
                  << " from=" << edge.from.to_string()
                  << " to=" << edge.to.to_string()
                  << " reason=" << route_provenance::to_string(edge.reason) << "\n";
      }
    }
    return 0;
  }
  if (arguments.command == "ancestry" || arguments.command == "descendants") {
    route_provenance::TraversalBounds bounds;
    bounds.max_depth = arguments.depth;
    bounds.max_results = arguments.limit;
    const route_provenance::Result<route_provenance::TraversalResult> traversal =
        arguments.command == "ancestry"
            ? store.ancestors(route_provenance::ProvenanceNodeId::from_value(arguments.node), bounds)
            : store.descendants(route_provenance::ProvenanceNodeId::from_value(arguments.node), bounds);
    if (!traversal.has_value()) {
      std::cout << "outcome=" << route_provenance::to_string(traversal.outcome())
                << " detail=" << traversal.detail() << "\n";
      return 3;
    }
    std::vector<route_provenance::ProvenanceNode> nodes;
    for (const route_provenance::TraversalEntry& entry : traversal.value().nodes) {
      nodes.push_back(entry.node);
    }
    print_nodes(nodes);
    return 0;
  }
  if (arguments.command == "cause") {
    route_provenance::ExplainRequest request;
    request.subject = route_provenance::ProvenanceNodeId::from_value(arguments.node);
    request.mode = route_provenance::parse_explain_mode(arguments.mode)
                       .value_or(route_provenance::ExplainMode::FullAncestry);
    request.max_depth = arguments.depth;
    request.max_nodes = arguments.limit;
    const route_provenance::Result<route_provenance::Explanation> explanation = store.explain(request);
    if (!explanation.has_value()) {
      std::cout << "outcome=" << route_provenance::to_string(explanation.outcome())
                << " detail=" << explanation.detail() << "\n";
      return 3;
    }
    std::cout << route_provenance::render_explanation(explanation.value());
    return 0;
  }
  if (arguments.command == "snapshot") {
    route_provenance::SnapshotOptions options;
    options.max_nodes = arguments.limit;
    const route_provenance::Result<route_provenance::Snapshot> snapshot =
        store.snapshot(route_provenance::RouteLineageId::from_value(arguments.lineage), options);
    if (!snapshot.has_value()) {
      std::cout << "outcome=" << route_provenance::to_string(snapshot.outcome())
                << " detail=" << snapshot.detail() << "\n";
      return 3;
    }
    std::cout << "snapshot id=" << snapshot.value().id.to_string()
              << " lineage=" << snapshot.value().lineage.to_string()
              << " current_generation=" << snapshot.value().current_route_generation.to_string()
              << " currentness=" << route_provenance::to_string(snapshot.value().current_currentness)
              << " nodes=" << snapshot.value().nodes.size()
              << " edges=" << snapshot.value().edges.size()
              << " digest=" << snapshot.value().digest.hex() << "\n";
    print_nodes(snapshot.value().nodes);
    return 0;
  }
  usage();
  return 2;
}