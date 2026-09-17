// Route Provenance publisher process.
//
// Connects to a coordinator, registers a worker boot, and executes a deterministic script of
// provenance publications and administrative actions. Output is line-oriented and script
// friendly so that a harness can synchronise on real process behaviour.
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "route_provenance/runtime.hpp"
#include "route_provenance/version.hpp"

namespace {

using route_provenance::Digest;
using route_provenance::EvidenceEntry;
using route_provenance::EvidenceField;
using route_provenance::EvidenceVector;
using route_provenance::Outcome;
using route_provenance::PublicationPayload;
using route_provenance::ReasonCode;
using route_provenance::RegistrationPayload;
using route_provenance::SourceClass;

struct Options {
  std::string address = "127.0.0.1";
  std::uint16_t port = 0;
  std::uint64_t publisher = 0;
  std::uint64_t boot = 0;
  std::uint64_t epoch = 0;
  /// Attempt identifiers are scoped to the publisher, so a fresh worker boot starts a fresh
  /// attempt range: replaying a boot's attempt numbers with different payloads would be a
  /// conflict by definition.
  std::uint64_t attempt_base = 0;
  std::string script;
  route_provenance::Limits limits;
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

[[nodiscard]] std::vector<std::string> split(const std::string& text, char separator) {
  std::vector<std::string> parts;
  std::string current;
  for (const char ch : text) {
    if (ch == separator) {
      parts.push_back(current);
      current.clear();
      continue;
    }
    current.push_back(ch);
  }
  parts.push_back(current);
  return parts;
}

[[nodiscard]] bool parse_key_value(const std::string& token, std::string& key, std::string& value) {
  const std::size_t position = token.find('=');
  if (position == std::string::npos) {
    return false;
  }
  key = token.substr(0, position);
  value = token.substr(position + 1);
  return true;
}

struct PublisherState {
  route_provenance::ProvenanceClient* client = nullptr;
  std::uint64_t attempt = 1;
  route_provenance::RouteId route;
  std::string key;
  route_provenance::RouteGeneration generation;
  route_provenance::ProvenanceNodeId last_node;
  route_provenance::RouteLineageId lineage;
  int exit_code = 0;
  bool registered = false;

  [[nodiscard]] route_provenance::AuthorityContext authority(route_provenance::PublisherId publisher,
                                                            route_provenance::WorkerBootId boot,
                                                            route_provenance::CoordinatorEpoch epoch,
                                                            route_provenance::AuthorityScope scope) {
    route_provenance::AuthorityContext context;
    context.publisher =
        route_provenance::PublisherIdentity{publisher, boot, epoch};
    context.scope = route_provenance::AuthorityScope::lineage(lineage);
    context.attempt = route_provenance::MutationAttemptId::from_value(attempt++);
    static_cast<void>(scope);
    return context;
  }
};

void usage() {
  std::cout << "usage: rp_publisher --connect <ip:port> --publisher N --boot N --epoch N "
               "--script <file>\n";
}

}  // namespace

int main(int argc, char** argv) {
  Options options;
  std::string endpoint;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    const auto next = [&](std::string& target) {
      if (i + 1 < argc) {
        target = argv[++i];
      }
    };
    std::string value;
    if (arg == "--connect") {
      next(endpoint);
    } else if (arg == "--publisher") {
      next(value);
      if (!parse_u64(value, options.publisher)) {
        std::cerr << "invalid --publisher\n";
        return 2;
      }
    } else if (arg == "--boot") {
      next(value);
      if (!parse_u64(value, options.boot)) {
        std::cerr << "invalid --boot\n";
        return 2;
      }
    } else if (arg == "--epoch") {
      next(value);
      if (!parse_u64(value, options.epoch)) {
        std::cerr << "invalid --epoch\n";
        return 2;
      }
    } else if (arg == "--attempt-base") {
      next(value);
      if (!parse_u64(value, options.attempt_base)) {
        std::cerr << "invalid --attempt-base\n";
        return 2;
      }
    } else if (arg == "--script") {
      next(options.script);
    } else if (arg == "--help" || arg == "-h") {
      usage();
      return 0;
    } else {
      std::cerr << "unknown argument: " << arg << "\n";
      usage();
      return 2;
    }
  }
  if (endpoint.empty() || options.publisher == 0 || options.boot == 0 || options.epoch == 0 ||
      options.script.empty()) {
    std::cerr << "missing required arguments\n";
    usage();
    return 2;
  }
  const std::vector<std::string> endpoint_parts = split(endpoint, ':');
  if (endpoint_parts.size() != 2) {
    std::cerr << "invalid --connect endpoint\n";
    return 2;
  }
  options.address = endpoint_parts[0];
  std::uint64_t port = 0;
  if (!parse_u64(endpoint_parts[1], port) || port == 0 || port > 65535U) {
    std::cerr << "invalid --connect port\n";
    return 2;
  }
  options.port = static_cast<std::uint16_t>(port);

  const route_provenance::PublisherId publisher = route_provenance::PublisherId::from_value(options.publisher);
  const route_provenance::WorkerBootId boot = route_provenance::WorkerBootId::from_value(options.boot);
  const route_provenance::CoordinatorEpoch epoch = route_provenance::CoordinatorEpoch::from_value(options.epoch);

  route_provenance::ClientOptions client_options;
  client_options.address = options.address;
  client_options.port = options.port;
  client_options.limits = options.limits;
  route_provenance::ProvenanceClient client(client_options);
  std::string error;
  const route_provenance::Status connected = client.connect(error);
  if (!connected.is_ok()) {
    std::cout << "CONNECT outcome=" << route_provenance::to_string(connected.outcome())
              << " detail=" << error << "\n";
    return 3;
  }

  PublisherState state;
  state.client = &client;
  state.attempt = options.attempt_base == 0 ? options.boot * 1000000ULL : options.attempt_base;

  std::ifstream script(options.script, std::ios::binary);
  if (!script) {
    std::cout << "SCRIPT outcome=IO_FAILURE detail=cannot open script\n";
    return 3;
  }

  std::string line;
  while (std::getline(script, line)) {
    if (line.empty() || line[0] == '#') {
      continue;
    }
    std::istringstream stream(line);
    std::string command;
    stream >> command;

    if (command == "register") {
      RegistrationPayload registration;
      registration.role = 1;
      registration.identity = route_provenance::PublisherIdentity{publisher, boot, epoch};
      registration.scope = route_provenance::AuthorityScope::fabric();
      const route_provenance::Result<route_provenance::HelloAckPayload> ack = client.hello(registration);
      if (!ack.has_value()) {
        std::cout << "REGISTER outcome=" << route_provenance::to_string(ack.outcome())
                  << " detail=" << ack.detail() << "\n";
        return 4;
      }
      state.registered = ack.value().accepted;
      std::cout << "REGISTER accepted=" << (ack.value().accepted ? "true" : "false")
                << " epoch=" << ack.value().epoch.to_string()
                << " detail=" << ack.value().detail << "\n";
      std::cout.flush();
      continue;
    }

    if (command == "publish") {
      PublicationPayload payload;
      std::string token;
      bool has_root = false;
      bool has_edge = false;
      bool has_predecessor = false;
      route_provenance::EdgeSpec edge;
      while (stream >> token) {
        std::string key;
        std::string value;
        if (!parse_key_value(token, key, value)) {
          continue;
        }
        if (key == "gen") {
          std::uint64_t parsed = 0;
          static_cast<void>(parse_u64(value, parsed));
          payload.route_generation = route_provenance::RouteGeneration::from_value(parsed);
        } else if (key == "reason") {
          const std::optional<ReasonCode> parsed = route_provenance::parse_reason_code(value);
          if (parsed.has_value()) {
            payload.reason = *parsed;
          }
        } else if (key == "source") {
          const std::optional<SourceClass> parsed = route_provenance::parse_source_class(value);
          if (parsed.has_value()) {
            payload.source = *parsed;
          }
        } else if (key == "root") {
          const std::optional<route_provenance::RootReason> parsed = route_provenance::parse_root_reason(value);
          if (parsed.has_value()) {
            payload.root_reason = *parsed;
            has_root = true;
          }
        } else if (key == "path") {
          const std::vector<std::string> parts = split(value, ':');
          if (parts.size() == 2) {
            route_provenance::PathBinding binding;
            std::uint64_t first = 0;
            std::uint64_t second = 0;
            static_cast<void>(parse_u64(parts[0], first));
            static_cast<void>(parse_u64(parts[1], second));
            binding.path = route_provenance::PathId::from_value(first);
            binding.generation = route_provenance::PathAuthorityGeneration::from_value(second);
            binding.decision_digest = Digest::hash(std::string("path-authority:") + value);
            payload.bindings.path = binding;
          }
        } else if (key == "policy") {
          std::uint64_t parsed = 0;
          static_cast<void>(parse_u64(value, parsed));
          route_provenance::PolicyBinding binding;
          binding.generation = route_provenance::PolicyGeneration::from_value(parsed);
          payload.bindings.policy = binding;
        } else if (key == "adapt") {
          const std::vector<std::string> parts = split(value, ':');
          if (parts.size() == 4) {
            route_provenance::AdaptationBinding binding;
            std::uint64_t decision = 0;
            std::uint64_t generation = 0;
            std::uint64_t policy = 0;
            std::uint64_t evidence = 0;
            static_cast<void>(parse_u64(parts[0], decision));
            static_cast<void>(parse_u64(parts[1], generation));
            static_cast<void>(parse_u64(parts[2], policy));
            static_cast<void>(parse_u64(parts[3], evidence));
            binding.decision = route_provenance::AdaptationDecisionId::from_value(decision);
            binding.generation = route_provenance::AdaptationGeneration::from_value(generation);
            binding.policy = route_provenance::PolicyGeneration::from_value(policy);
            binding.evidence = route_provenance::EvidenceGeneration::from_value(evidence);
            binding.decision_digest = Digest::hash(std::string("adaptation:") + value);
            payload.bindings.adaptation = binding;
          }
        } else if (key == "conv") {
          const std::vector<std::string> parts = split(value, ':');
          if (parts.size() == 3) {
            route_provenance::ConvergenceBinding binding;
            std::uint64_t plan = 0;
            std::uint64_t generation = 0;
            std::uint64_t step = 0;
            static_cast<void>(parse_u64(parts[0], plan));
            static_cast<void>(parse_u64(parts[1], generation));
            static_cast<void>(parse_u64(parts[2], step));
            binding.plan = route_provenance::ConvergencePlanId::from_value(plan);
            binding.generation = route_provenance::ConvergencePlanGeneration::from_value(generation);
            binding.step = route_provenance::ConvergenceStepId::from_value(step);
            binding.completion_evidence = Digest::hash(std::string("convergence:") + value);
            payload.bindings.convergence = binding;
          }
        } else if (key == "ecmp") {
          const std::vector<std::string> parts = split(value, ':');
          if (parts.size() == 3) {
            route_provenance::EcmpBinding binding;
            std::uint64_t group = 0;
            std::uint64_t membership = 0;
            std::uint64_t assignment = 0;
            static_cast<void>(parse_u64(parts[0], group));
            static_cast<void>(parse_u64(parts[1], membership));
            static_cast<void>(parse_u64(parts[2], assignment));
            binding.group = route_provenance::EcmpGroupId::from_value(group);
            binding.membership = route_provenance::MembershipGeneration::from_value(membership);
            binding.assignment = route_provenance::AssignmentGeneration::from_value(assignment);
            payload.bindings.ecmp = binding;
          }
        } else if (key == "weight") {
          const std::vector<std::string> parts = split(value, ':');
          if (parts.size() == 3) {
            route_provenance::WeightedPathBinding binding;
            std::uint64_t set = 0;
            std::uint64_t policy = 0;
            std::uint64_t assignment = 0;
            static_cast<void>(parse_u64(parts[0], set));
            static_cast<void>(parse_u64(parts[1], policy));
            static_cast<void>(parse_u64(parts[2], assignment));
            binding.set = route_provenance::WeightedPathSetId::from_value(set);
            binding.policy = route_provenance::WeightPolicyGeneration::from_value(policy);
            binding.assignment = route_provenance::AssignmentGeneration::from_value(assignment);
            payload.bindings.weighted = binding;
          }
        } else if (key == "edge") {
          const std::vector<std::string> parts = split(value, ':');
          if (parts.size() == 2) {
            const std::optional<route_provenance::EdgeType> type = route_provenance::parse_edge_type(parts[0]);
            std::uint64_t target = 0;
            if (type.has_value() && parse_u64(parts[1], target)) {
              edge.type = *type;
              edge.target = route_provenance::ProvenanceNodeId::from_value(target);
              edge.reason = payload.reason;
              edge.source = payload.source;
              has_edge = true;
            }
          }
        }
      }

      payload.key.route = state.route;
      payload.key.semantic_key = state.key;
      payload.route_state_digest = Digest::hash("route-state:" + state.key + ":" +
                                                payload.route_generation.to_string());
      if (!has_edge && !has_root && state.lineage.valid()) {
        const route_provenance::Result<route_provenance::LineageView> view = client.query_lineage(state.lineage);
        if (view.has_value() && view.value().current_node.valid()) {
          edge.type = route_provenance::EdgeType::Supersedes;
          edge.target = view.value().current_node;
          edge.reason = payload.reason;
          edge.source = payload.source;
          has_edge = true;
          has_predecessor = true;
        }
      }
      if (has_edge) {
        payload.edges.push_back(edge);
      }
      static_cast<void>(has_predecessor);
      payload.authority = state.authority(publisher, boot, epoch, route_provenance::AuthorityScope::fabric());
      const route_provenance::Result<route_provenance::Publication> result = client.publish(payload);
      if (result.has_value()) {
        state.last_node = result.value().node;
        state.lineage = result.value().lineage;
        state.generation = payload.route_generation;
      }
      std::cout << "PUBLISH gen=" << payload.route_generation.to_string()
                << " outcome=" << route_provenance::to_string(result.outcome())
                << " node=" << (result.has_value() ? result.value().node.to_string() : "0")
                << " lineage=" << (result.has_value() ? result.value().lineage.to_string() : "0")
                << " currentness="
                << (result.has_value() ? std::string(route_provenance::to_string(result.value().currentness))
                                       : std::string("NONE"));
      if (!result.has_value() && !result.detail().empty()) {
        std::cout << " detail=" << result.detail();
      }
      std::cout << "\n";
      std::cout.flush();
      continue;
    }

    if (command == "lineage") {
      std::string key;
      std::uint64_t route = 0;
      stream >> route >> key;
      state.route = route_provenance::RouteId::from_value(route);
      state.key = key;
      state.lineage = route_provenance::derive_lineage_id(route_provenance::LineageKey{state.route, key});
      std::cout << "LINEAGE id=" << state.lineage.to_string() << "\n";
      std::cout.flush();
      continue;
    }

    if (command == "declare") {
      std::string kind;
      stream >> kind;
      route_provenance::DeclarationPayload payload;
      payload.key.route = state.route;
      payload.key.semantic_key = state.key;
      std::uint64_t a = 0;
      std::uint64_t b = 0;
      std::uint64_t c = 0;
      if (kind == "path") {
        stream >> a >> b;
        payload.kind = route_provenance::NodeKind::PathAuthorization;
        payload.source = SourceClass::PathAuthority;
        route_provenance::PathBinding binding;
        binding.path = route_provenance::PathId::from_value(a);
        binding.generation = route_provenance::PathAuthorityGeneration::from_value(b);
        binding.decision_digest = Digest::hash("path-authority:" + std::to_string(a) + ":" + std::to_string(b));
        payload.bindings.path = binding;
      } else if (kind == "planner") {
        stream >> a >> b >> c;
        payload.kind = route_provenance::NodeKind::PlannerCandidate;
        payload.source = SourceClass::PathPlanner;
        route_provenance::PlannerBinding binding;
        binding.request = route_provenance::PlannerRequestId::from_value(a);
        binding.generation = route_provenance::PlannerGeneration::from_value(b);
        binding.candidate_rank = static_cast<std::uint32_t>(c);
        binding.selected_path = route_provenance::PathId::from_value(a);
        binding.plan_digest = Digest::hash("planner:" + std::to_string(a) + ":" + std::to_string(b));
        payload.bindings.planner = binding;
      } else if (kind == "adaptive") {
        std::uint64_t d = 0;
        stream >> a >> b >> c >> d;
        payload.kind = route_provenance::NodeKind::AdaptiveDecision;
        payload.source = SourceClass::AdaptiveRouting;
        route_provenance::AdaptationBinding binding;
        binding.decision = route_provenance::AdaptationDecisionId::from_value(a);
        binding.generation = route_provenance::AdaptationGeneration::from_value(b);
        binding.policy = route_provenance::PolicyGeneration::from_value(c);
        binding.evidence = route_provenance::EvidenceGeneration::from_value(d);
        binding.decision_digest = Digest::hash("adaptation:" + std::to_string(a));
        payload.bindings.adaptation = binding;
      } else if (kind == "convergence") {
        stream >> a >> b >> c;
        payload.kind = route_provenance::NodeKind::ConvergencePlan;
        payload.source = SourceClass::RouteConvergence;
        route_provenance::ConvergenceBinding binding;
        binding.plan = route_provenance::ConvergencePlanId::from_value(a);
        binding.generation = route_provenance::ConvergencePlanGeneration::from_value(b);
        binding.step = route_provenance::ConvergenceStepId::from_value(c);
        binding.completion_evidence = Digest::hash("convergence:" + std::to_string(a));
        payload.bindings.convergence = binding;
      } else if (kind == "policy") {
        stream >> a;
        payload.kind = route_provenance::NodeKind::PolicyDecision;
        payload.source = SourceClass::Administrative;
        route_provenance::PolicyBinding binding;
        binding.generation = route_provenance::PolicyGeneration::from_value(a);
        payload.bindings.policy = binding;
      } else {
        std::cout << "DECLARE outcome=MALFORMED_REQUEST\n";
        std::cout.flush();
        continue;
      }
      payload.authority = state.authority(publisher, boot, epoch, route_provenance::AuthorityScope::fabric());
      const route_provenance::Result<route_provenance::Publication> result = client.declare(payload);
      if (result.has_value()) {
        state.last_node = result.value().node;
        state.lineage = result.value().lineage;
      }
      std::cout << "DECLARE kind=" << kind << " outcome=" << route_provenance::to_string(result.outcome())
                << " node=" << (result.has_value() ? result.value().node.to_string() : "0") << "\n";
      std::cout.flush();
      continue;
    }

    if (command == "link") {
      std::string type;
      std::uint64_t from = 0;
      std::uint64_t to = 0;
      stream >> type >> from >> to;
      route_provenance::LinkPayload payload;
      payload.key.route = state.route;
      payload.key.semantic_key = state.key;
      const std::optional<route_provenance::EdgeType> parsed = route_provenance::parse_edge_type(type);
      payload.type = parsed.value_or(route_provenance::EdgeType::AuthorizedBy);
      payload.from = route_provenance::ProvenanceNodeId::from_value(from);
      payload.to = route_provenance::ProvenanceNodeId::from_value(to);
      payload.authority = state.authority(publisher, boot, epoch, route_provenance::AuthorityScope::fabric());
      const route_provenance::Result<route_provenance::Publication> result = client.link(payload);
      std::cout << "LINK outcome=" << route_provenance::to_string(result.outcome()) << "\n";
      std::cout.flush();
      continue;
    }

    const auto administrative = [&](route_provenance::MessageId message, ReasonCode reason) {
      std::uint64_t target = 0;
      stream >> target;
      route_provenance::AdministrativePayload payload;
      payload.key.route = state.route;
      payload.key.semantic_key = state.key;
      payload.target = route_provenance::ProvenanceNodeId::from_value(target);
      payload.reason = reason;
      payload.source = SourceClass::Administrative;
      payload.authority = state.authority(publisher, boot, epoch, route_provenance::AuthorityScope::fabric());
      payload.allow_non_current_target = true;
      const route_provenance::Result<route_provenance::Publication> result =
          client.administrative(message, payload);
      std::cout << "ADMIN op=" << route_provenance::to_string(message)
                << " outcome=" << route_provenance::to_string(result.outcome())
                << " node=" << (result.has_value() ? result.value().node.to_string() : "0") << "\n";
      std::cout.flush();
    };

    if (command == "withdraw") {
      administrative(route_provenance::MessageId::Withdraw, ReasonCode::AdminWithdrawal);
      continue;
    }
    if (command == "revoke") {
      administrative(route_provenance::MessageId::Revoke, ReasonCode::Revocation);
      continue;
    }
    if (command == "retire") {
      administrative(route_provenance::MessageId::Retire, ReasonCode::Retirement);
      continue;
    }
    if (command == "revalidate") {
      administrative(route_provenance::MessageId::Revalidate, ReasonCode::RecoveryRevalidation);
      continue;
    }
    if (command == "invalidate") {
      administrative(route_provenance::MessageId::Invalidate, ReasonCode::Invalidation);
      continue;
    }
    if (command == "correct") {
      std::uint64_t target = 0;
      stream >> target;
      route_provenance::CorrectionPayload payload;
      payload.key.route = state.route;
      payload.key.semantic_key = state.key;
      payload.target = route_provenance::ProvenanceNodeId::from_value(target);
      payload.source = SourceClass::Administrative;
      payload.authority = state.authority(publisher, boot, epoch, route_provenance::AuthorityScope::fabric());
      const route_provenance::Result<route_provenance::Publication> result = client.correct(payload);
      std::cout << "ADMIN op=CORRECT outcome=" << route_provenance::to_string(result.outcome())
                << " node=" << (result.has_value() ? result.value().node.to_string() : "0") << "\n";
      std::cout.flush();
      continue;
    }

    if (command == "query-lineage") {
      std::uint64_t id = 0;
      stream >> id;
      const route_provenance::Result<route_provenance::LineageView> view =
          client.query_lineage(route_provenance::RouteLineageId::from_value(id));
      if (view.has_value()) {
        std::cout << "LINEAGE id=" << view.value().id.to_string()
                  << " lifecycle=" << route_provenance::to_string(view.value().lifecycle)
                  << " current_generation=" << view.value().current_route_generation.to_string()
                  << " current_node=" << view.value().current_node.to_string()
                  << " nodes=" << view.value().node_count
                  << " nodes_currentness="
                  << route_provenance::to_string(view.value().current_currentness)
                  << " lineage_generation=" << view.value().lineage_generation.to_string() << "\n";
      } else {
        std::cout << "LINEAGE outcome=" << route_provenance::to_string(view.outcome())
                  << " detail=" << view.detail() << "\n";
      }
      std::cout.flush();
      continue;
    }

    if (command == "cause") {
      std::uint64_t node = 0;
      stream >> node;
      route_provenance::QueryPayload query;
      query.node = route_provenance::ProvenanceNodeId::from_value(node);
      query.mode = route_provenance::ExplainMode::FullAncestry;
      const route_provenance::Result<route_provenance::Explanation> explanation = client.query_cause(query);
      if (explanation.has_value()) {
        std::cout << "CAUSE subject=" << explanation.value().subject.to_string()
                  << " steps=" << explanation.value().steps.size()
                  << " current=" << (explanation.value().current ? "true" : "false")
                  << " historically_valid=" << (explanation.value().historically_valid ? "true" : "false")
                  << " currentness=" << route_provenance::to_string(explanation.value().subject_currentness)
                  << "\n";
        for (const route_provenance::ExplanationStep& step : explanation.value().steps) {
          std::cout << "CAUSE_STEP depth=" << step.depth
                    << " type=" << route_provenance::to_string(step.type)
                    << " node=" << step.to.to_string()
                    << " reason=" << route_provenance::to_string(step.reason) << "\n";
        }
      } else {
        std::cout << "CAUSE outcome=" << route_provenance::to_string(explanation.outcome())
                  << " detail=" << explanation.detail() << "\n";
      }
      std::cout.flush();
      continue;
    }

    if (command == "ancestry") {
      std::uint64_t node = 0;
      stream >> node;
      route_provenance::QueryPayload query;
      query.node = route_provenance::ProvenanceNodeId::from_value(node);
      query.direction = route_provenance::TraversalDirection::Outgoing;
      const route_provenance::Result<std::vector<route_provenance::ProvenanceNode>> nodes =
          client.query_traversal(query);
      std::cout << "ANCESTRY outcome=" << route_provenance::to_string(nodes.outcome())
                << " count=" << (nodes.has_value() ? nodes.value().size() : 0) << "\n";
      std::cout.flush();
      continue;
    }

    if (command == "snapshot") {
      std::uint64_t id = 0;
      stream >> id;
      const route_provenance::Result<route_provenance::Snapshot> snapshot =
          client.query_snapshot(route_provenance::RouteLineageId::from_value(id));
      std::cout << "SNAPSHOT outcome=" << route_provenance::to_string(snapshot.outcome())
                << " nodes=" << (snapshot.has_value() ? snapshot.value().nodes.size() : 0)
                << " edges=" << (snapshot.has_value() ? snapshot.value().edges.size() : 0)
                << " digest=" << (snapshot.has_value() ? snapshot.value().digest.hex() : std::string{})
                << "\n";
      std::cout.flush();
      continue;
    }

    if (command == "advance-path" || command == "advance-policy" || command == "advance-evidence") {
      std::uint64_t value = 0;
      stream >> value;
      route_provenance::DependencyPayload payload;
      payload.notification.authority =
          state.authority(publisher, boot, epoch, route_provenance::AuthorityScope::fabric());
      payload.notification.authority.scope = route_provenance::AuthorityScope::fabric();
      if (command == "advance-path") {
        payload.notification.kind = route_provenance::DependencyKind::PathAuthorityAdvance;
        payload.notification.path_authority_generation =
            route_provenance::PathAuthorityGeneration::from_value(value);
      } else if (command == "advance-policy") {
        payload.notification.kind = route_provenance::DependencyKind::PolicyAdvance;
        payload.notification.policy_generation = route_provenance::PolicyGeneration::from_value(value);
      } else {
        payload.notification.kind = route_provenance::DependencyKind::EvidenceAdvance;
        payload.notification.evidence_generation =
            route_provenance::EvidenceGeneration::from_value(value);
      }
      const route_provenance::Status status = client.notify_dependency(payload);
      std::cout << "NOTIFY op=" << command
                << " outcome=" << route_provenance::to_string(status.outcome()) << "\n";
      std::cout.flush();
      continue;
    }

    if (command == "watermarks") {
      const route_provenance::Result<route_provenance::DependencyWatermarks> marks = client.watermarks();
      if (marks.has_value()) {
        std::cout << "WATERMARKS store=" << marks.value().store_generation.to_string()
                  << " path=" << marks.value().path_authority_generation.to_string()
                  << " policy=" << marks.value().policy_generation.to_string()
                  << " evidence=" << marks.value().evidence_generation.to_string()
                  << " epoch=" << marks.value().epoch.to_string() << "\n";
      } else {
        std::cout << "WATERMARKS outcome=" << route_provenance::to_string(marks.outcome()) << "\n";
      }
      std::cout.flush();
      continue;
    }

    if (command == "echo") {
      std::string text;
      std::getline(stream, text);
      std::cout << "ECHO" << text << "\n";
      std::cout.flush();
      continue;
    }

    if (command == "wait") {
      std::cout << "WAITING\n";
      std::cout.flush();
      std::string ignore;
      while (std::getline(std::cin, ignore)) {
        // Held open until the harness terminates this process.
      }
      std::cout << "WAIT_ENDED\n";
      std::cout.flush();
      continue;
    }

    if (command == "quit") {
      break;
    }

    std::cout << "UNKNOWN_COMMAND " << command << "\n";
    std::cout.flush();
  }

  std::cout << "PUBLISHER_DONE\n";
  std::cout.flush();
  return state.exit_code;
}