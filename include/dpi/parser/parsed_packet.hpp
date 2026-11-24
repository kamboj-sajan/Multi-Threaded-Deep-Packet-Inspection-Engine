#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>

#include "dpi/common/bytes.hpp"

namespace dpi {

namespace ethertype {
inline constexpr std::uint16_t kIpv4 = 0x0800;
inline constexpr std::uint16_t kArp = 0x0806;
inline constexpr std::uint16_t kVlan = 0x8100;
inline constexpr std::uint16_t kIpv6 = 0x86DD;
}  // namespace ethertype

namespace ipproto {
inline constexpr std::uint8_t kIcmp = 1;
inline constexpr std::uint8_t kTcp = 6;
inline constexpr std::uint8_t kUdp = 17;
}  // namespace ipproto

namespace tcpflag {
inline constexpr std::uint8_t kFin = 0x01;
inline constexpr std::uint8_t kSyn = 0x02;
inline constexpr std::uint8_t kRst = 0x04;
inline constexpr std::uint8_t kPsh = 0x08;
inline constexpr std::uint8_t kAck = 0x10;
}  // namespace tcpflag

// Why a packet could not be parsed. Every value except Ok means the packet
// is malformed: it is counted under this reason and never forwarded.
enum class ParseStatus : std::uint8_t {
  Ok,
  TruncatedEthernet,
  TruncatedVlan,
  TruncatedIpv4,
  BadIpVersion,
  BadIpHeaderLength,
  BadIpTotalLength,
  TruncatedTcp,
  BadTcpDataOffset,
  TruncatedUdp,
  BadUdpLength,
};
inline constexpr std::size_t kParseStatusCount = 11;

const char* to_string(ParseStatus status) noexcept;

enum class L3Kind : std::uint8_t {
  NonIp,  // ARP, IPv6, LLDP...: well formed but not inspected; forwarded.
  Ipv4,
};

enum class L4Kind : std::uint8_t {
  None,   // No transport header: not IPv4, or a non-first IP fragment.
  Tcp,
  Udp,
  Other,  // ICMP, GRE, ...: IPv4 payload without ports.
};

// The un-normalised addressing of one packet, in host byte order.
struct PacketTuple {
  std::uint32_t src_ip = 0;
  std::uint32_t dst_ip = 0;
  std::uint16_t src_port = 0;
  std::uint16_t dst_port = 0;
  std::uint8_t protocol = 0;

  bool operator==(const PacketTuple&) const = default;
};

// Result of decoding L2-L4. It stores offsets into the frame, not pointers,
// so it stays valid when the owning Packet is moved between threads.
struct ParsedPacket {
  // Layer 2
  std::uint16_t ethertype = 0;  // After any VLAN tag.
  bool has_vlan = false;
  std::uint16_t vlan_id = 0;

  // Layer 3
  L3Kind l3 = L3Kind::NonIp;
  std::uint32_t l3_offset = 0;
  std::uint32_t src_ip = 0;
  std::uint32_t dst_ip = 0;
  std::uint8_t protocol = 0;
  std::uint8_t ttl = 0;
  std::uint16_t ip_header_len = 0;
  std::uint16_t ip_total_len = 0;
  bool is_fragment = false;
  bool more_fragments = false;
  std::uint16_t fragment_offset = 0;  // In bytes.

  // Layer 4
  L4Kind l4 = L4Kind::None;
  std::uint32_t l4_offset = 0;
  std::uint16_t src_port = 0;
  std::uint16_t dst_port = 0;
  std::uint8_t tcp_flags = 0;
  std::uint16_t tcp_header_len = 0;
  std::uint32_t tcp_seq = 0;

  // Application payload. payload_truncated means the capture (snaplen)
  // cut the packet short, so payload_len counts only captured bytes.
  std::uint32_t payload_offset = 0;
  std::uint32_t payload_len = 0;
  bool payload_truncated = false;

  bool has_ports() const noexcept { return l4 == L4Kind::Tcp || l4 == L4Kind::Udp; }

  PacketTuple tuple() const noexcept {
    return PacketTuple{src_ip, dst_ip, src_port, dst_port, protocol};
  }

  // `frame` must be the bytes this ParsedPacket was produced from.
  ByteView payload(ByteView frame) const noexcept {
    assert(payload_offset + payload_len <= frame.size());
    return frame.subspan(payload_offset, payload_len);
  }
};

}  // namespace dpi
