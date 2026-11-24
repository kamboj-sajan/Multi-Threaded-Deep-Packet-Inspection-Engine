#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "dpi/common/types.hpp"
#include "dpi/flow/five_tuple.hpp"
#include "dpi/flow/tcp_tracker.hpp"

namespace dpi {

struct DirectionCounters {
  std::uint64_t packets = 0;
  std::uint64_t bytes = 0;
};

// Everything the fast path knows about one bidirectional flow.
struct FlowEntry {
  FiveTuple key;
  // Direction of client->server traffic. The client is whoever sent the
  // first packet we saw, except that a leading SYN-ACK identifies the
  // server (we missed the SYN).
  Direction client_direction = Direction::LoToHi;

  std::uint64_t first_seen_ns = 0;
  std::uint64_t last_seen_ns = 0;
  DirectionCounters to_server;
  DirectionCounters to_client;
  TcpTracker tcp;

  // Deep-inspection results.
  AppId app = AppId::Unknown;
  std::string sni;              // TLS SNI or HTTP Host, lower-cased.
  std::uint8_t payload_packets_inspected = 0;
  bool inspection_done = false;  // Classified, or gave up: fast path from now on.
  Verdict verdict = Verdict::Forward;

  // Minimal reassembly of the client's first bytes, used only while a
  // ClientHello / HTTP request is split across TCP segments. Empty (and
  // unallocated) for almost every flow.
  std::vector<std::uint8_t> pending_client_bytes;
  std::uint32_t next_client_seq = 0;

  bool is_from_client(Direction d) const noexcept { return d == client_direction; }

  // The port the client connected to.
  std::uint16_t server_port() const noexcept {
    return client_direction == Direction::LoToHi ? key.port_hi : key.port_lo;
  }

  void account(Direction d, std::uint32_t bytes, std::uint64_t ts_ns) noexcept {
    DirectionCounters& c = is_from_client(d) ? to_server : to_client;
    ++c.packets;
    c.bytes += bytes;
    last_seen_ns = ts_ns;
  }

  std::uint64_t total_packets() const noexcept { return to_server.packets + to_client.packets; }
  std::uint64_t total_bytes() const noexcept { return to_server.bytes + to_client.bytes; }
};

// Decides the client direction for a brand-new flow from its first packet.
inline Direction initial_client_direction(Direction first_packet, std::uint8_t protocol,
                                          std::uint8_t tcp_flags) noexcept {
  const bool syn_ack = (tcp_flags & 0x12) == 0x12;  // SYN|ACK
  return protocol == 6 && syn_ack ? opposite(first_packet) : first_packet;
}

}  // namespace dpi
