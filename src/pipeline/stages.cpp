#include "dpi/pipeline/stages.hpp"

namespace dpi {

std::uint64_t routing_hash(ByteView frame) noexcept {
  const std::optional<PacketTuple> tuple = peek_tuple(frame);
  return tuple ? flow_hash(normalize(*tuple).key) : 0;
}

// --- ReaderStage ------------------------------------------------------------

bool ReaderStage::next(RoutedPacket& out) {
  switch (reader_.next(out.packet)) {
    case ReadStatus::Ok:
      ++stats_.packets;
      stats_.bytes += out.packet.caplen();
      out.hash = routing_hash(out.packet.data());
      return true;
    case ReadStatus::TruncatedRecord:
      ++stats_.truncated_records;
      return false;
    case ReadStatus::CorruptRecord:
      ++stats_.corrupt_records;
      return false;
    case ReadStatus::EndOfFile:
      return false;
  }
  return false;
}

// --- LoadBalancerStage ------------------------------------------------------

std::optional<WorkItem> LoadBalancerStage::process(RoutedPacket&& in) {
  ++stats_.packets;
  WorkItem item;
  const ParseStatus status = parse_packet(in.packet.data(), in.packet.orig_len, item.parsed);
  if (status != ParseStatus::Ok) {
    ++stats_.malformed;
    ++stats_.malformed_by_reason[static_cast<std::size_t>(status)];
    return std::nullopt;
  }
  item.packet = std::move(in.packet);
  item.hash = in.hash;
  return item;
}

// --- FastPathStage ----------------------------------------------------------

FastPathStage::FastPathStage(FastPathConfig config)
    : config_(config),
      inspector_(config.classifier ? *config.classifier : Classifier::builtin(), config.inspection),
      table_(config.flow_table) {
  table_.set_retire_callback([this](const FlowEntry& flow) { record_retired_flow(flow); });
}

Verdict FastPathStage::process(const Packet& packet, const ParsedPacket& parsed) {
  ++stats_.packets;
  stats_.bytes += packet.caplen();
  maybe_sweep(packet.ts_ns);

  Verdict verdict = Verdict::Forward;
  if (parsed.l3 == L3Kind::Ipv4) {
    const Tracked tracked = track_flow(packet, parsed);
    FlowEntry& flow = *tracked.flow;
    const bool was_inspected = flow.inspection_done;
    inspector_.inspect(flow, parsed, packet.data(), tracked.from_client);
    // Rules run when a flow appears (ip/port/port-based app rules can
    // block it from its first packet) and once more when inspection has
    // decided the app and host. Packets sent before that - the TCP
    // handshake, typically - are therefore forwarded.
    if (tracked.created || (!was_inspected && flow.inspection_done)) {
      apply_rules(flow);
    }
    verdict = flow.verdict;
  } else {
    ++stats_.non_ip;  // No flow to attach it to; carried through untouched.
  }

  if (verdict == Verdict::Forward) {
    ++stats_.forwarded;
  } else {
    ++stats_.dropped;
  }
  return verdict;
}

FastPathStage::Tracked FastPathStage::track_flow(const Packet& packet, const ParsedPacket& parsed) {
  const NormalizedTuple tuple = normalize(parsed.tuple());
  auto [flow, created] = table_.find_or_create(tuple.key, tuple.direction, parsed.tcp_flags, packet.ts_ns);

  // A bare SYN on a connection that already closed is the 5-tuple being
  // reused by a new connection, so it gets a fresh flow (and fresh
  // inspection) rather than inheriting the old verdict.
  const bool bare_syn = (parsed.tcp_flags & (tcpflag::kSyn | tcpflag::kAck)) == tcpflag::kSyn;
  if (parsed.l4 == L4Kind::Tcp && bare_syn && flow->tcp.is_terminal()) {
    flow = &table_.restart(*flow, tuple.direction, parsed.tcp_flags, packet.ts_ns);
    created = true;
  }
  if (created) {
    inspector_.on_new_flow(*flow, parsed);
  }

  const bool from_client = flow->is_from_client(tuple.direction);
  flow->account(tuple.direction, packet.caplen(), packet.ts_ns);
  if (parsed.l4 == L4Kind::Tcp) {
    flow->tcp.on_packet(parsed.tcp_flags, from_client);
  }
  return {flow, from_client, created};
}

void FastPathStage::apply_rules(FlowEntry& flow) const {
  if (!config_.rules || flow.verdict == Verdict::Drop) {
    return;  // no rules, or already blocked (verdicts are sticky)
  }
  const FlowFacts facts{flow.key.ip_lo, flow.key.ip_hi, flow.key.port_lo, flow.key.port_hi, flow.app, flow.sni};
  const BlockReason reason = config_.rules->evaluate(facts);
  if (reason != BlockReason::None) {
    flow.verdict = Verdict::Drop;
    flow.blocked_by = reason;
  }
}

void FastPathStage::record_retired_flow(const FlowEntry& flow) {
  AppCounters& app = stats_.apps[static_cast<std::size_t>(flow.app)];
  ++app.flows;
  app.packets += flow.total_packets();
  app.bytes += flow.total_bytes();
  if (!flow.sni.empty()) {
    ++stats_.sni_flows[flow.sni];
  }
  if (flow.verdict == Verdict::Drop) {
    ++stats_.flows_blocked;
    ++stats_.flows_blocked_by_reason[static_cast<std::size_t>(flow.blocked_by)];
  }
}

void FastPathStage::maybe_sweep(std::uint64_t now_ns) {
  // Sweeping is driven by capture time, so it behaves the same whether the
  // file is replayed at line rate or read from memory at 10x that.
  if (now_ns >= next_sweep_ns_) {
    table_.expire_idle(now_ns);
    next_sweep_ns_ = now_ns + config_.sweep_interval_ns;
  }
}

void FastPathStage::finish() {
  table_.retire_all();
  stats_.flows_created = table_.stats().created;
  stats_.flows_expired = table_.stats().expired_idle;
  stats_.flows_evicted = table_.stats().evicted_capacity;
}

// --- WriterStage ------------------------------------------------------------

void WriterStage::write(const Packet& packet) {
  writer_.write(packet);
  ++stats_.packets;
  stats_.bytes += packet.caplen();
}

}  // namespace dpi
