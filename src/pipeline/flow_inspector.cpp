#include "dpi/pipeline/flow_inspector.hpp"

#include <cstring>

#include "dpi/inspect/http_host.hpp"
#include "dpi/inspect/tls_sni.hpp"

namespace dpi {
namespace {

// Appends `bytes` to `buffer`. Written as resize + memcpy rather than
// vector::insert because GCC 13 at -O2 emits a false -Wstringop-overflow
// for range insert into std::vector<uint8_t>.
void append_bytes(std::vector<std::uint8_t>& buffer, ByteView bytes) {
  if (bytes.empty()) {
    return;
  }
  const std::size_t old_size = buffer.size();
  buffer.resize(old_size + bytes.size());
  std::memcpy(buffer.data() + old_size, bytes.data(), bytes.size());
}

}  // namespace

void FlowInspector::on_new_flow(FlowEntry& flow, const ParsedPacket& first) const {
  flow.app = Classifier::app_for_port(flow.key.protocol, flow.server_port());
  if (first.l4 != L4Kind::Tcp) {
    // Only TCP payloads are inspected (UDP DNS/QUIC are classified by
    // port), so these flows go straight to the fast path.
    flow.inspection_done = true;
  }
}

void FlowInspector::finish(FlowEntry& flow) {
  flow.inspection_done = true;
  // Free the reassembly buffer: the flow will never need it again.
  std::vector<std::uint8_t>().swap(flow.pending_client_bytes);
}

FlowInspector::Outcome FlowInspector::classify_client_bytes(FlowEntry& flow, ByteView data) const {
  const SniResult tls = parse_tls_client_hello(data);
  switch (tls.status) {
    case SniStatus::Found: {
      const AppId app = classifier_.app_for_host(tls.sni);
      flow.app = app == AppId::Unknown ? AppId::HTTPS : app;
      flow.sni = tls.sni;
      return Outcome::Classified;
    }
    case SniStatus::NoSni:
      flow.app = AppId::HTTPS;  // TLS, but nothing names the destination
      return Outcome::Classified;
    case SniStatus::Incomplete:
      return Outcome::NeedMoreBytes;
    case SniStatus::Malformed:
      return Outcome::NotRecognised;  // never trust a broken hello's SNI
    case SniStatus::NotClientHello:
      break;  // try HTTP next
  }

  const HttpHostResult http = parse_http_host(data);
  switch (http.status) {
    case HttpHostStatus::Found: {
      const AppId app = classifier_.app_for_host(http.host);
      flow.app = app == AppId::Unknown ? AppId::HTTP : app;
      flow.sni = http.host;
      return Outcome::Classified;
    }
    case HttpHostStatus::NoHost:
      flow.app = AppId::HTTP;
      return Outcome::Classified;
    case HttpHostStatus::Incomplete:
      return Outcome::NeedMoreBytes;
    case HttpHostStatus::NotHttp:
      break;
  }
  return Outcome::NotRecognised;
}

void FlowInspector::buffer_for_reassembly(FlowEntry& flow, const ParsedPacket& parsed,
                                          ByteView payload) const {
  // The first segment starts the buffer; later ones were already appended
  // by inspect().
  if (flow.pending_client_bytes.empty()) {
    append_bytes(flow.pending_client_bytes, payload);
  }
  // Reassembly needs every byte: a snaplen-cut segment, or a first
  // segment already over the cap, ends inspection (the port-based app
  // stays).
  if (parsed.payload_truncated || flow.pending_client_bytes.size() > config_.max_reassembly_bytes) {
    finish(flow);
    return;
  }
  flow.next_client_seq = parsed.tcp_seq + static_cast<std::uint32_t>(payload.size());
}

void FlowInspector::inspect(FlowEntry& flow, const ParsedPacket& parsed, ByteView frame,
                            bool from_client) const {
  if (flow.inspection_done || parsed.payload_len == 0) {
    return;  // already classified, or a pure ACK / handshake packet
  }
  ++flow.payload_packets_inspected;

  if (from_client) {
    const ByteView payload = parsed.payload(frame);
    ByteView data = payload;
    if (!flow.pending_client_bytes.empty()) {
      // Continuing a split message: only the exact next segment fits.
      // Anything else (retransmission, reordering, loss) ends inspection;
      // full TCP reassembly is out of scope.
      if (parsed.tcp_seq != flow.next_client_seq) {
        finish(flow);
        return;
      }
      // Enforce the memory cap before growing the buffer.
      if (flow.pending_client_bytes.size() + payload.size() > config_.max_reassembly_bytes) {
        finish(flow);
        return;
      }
      append_bytes(flow.pending_client_bytes, payload);
      data = flow.pending_client_bytes;
    }

    switch (classify_client_bytes(flow, data)) {
      case Outcome::Classified:
        finish(flow);
        return;
      case Outcome::NeedMoreBytes:
        buffer_for_reassembly(flow, parsed, payload);
        break;
      case Outcome::NotRecognised:
        finish(flow);  // e.g. SSH, BitTorrent: keep the port-based app
        return;
    }
  }

  if (!flow.inspection_done && flow.payload_packets_inspected >= config_.max_payload_packets) {
    finish(flow);
  }
}

}  // namespace dpi
