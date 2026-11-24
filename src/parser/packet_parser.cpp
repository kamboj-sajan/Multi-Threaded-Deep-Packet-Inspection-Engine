#include "dpi/parser/packet_parser.hpp"

#include <algorithm>

namespace dpi {
namespace {

constexpr std::size_t kEthernetHeaderLen = 14;
constexpr std::size_t kVlanTagLen = 4;
constexpr std::size_t kIpv4MinHeaderLen = 20;
constexpr std::size_t kTcpMinHeaderLen = 20;
constexpr std::size_t kUdpHeaderLen = 8;

constexpr std::uint16_t kIpMoreFragments = 0x2000;
constexpr std::uint16_t kIpFragmentOffsetMask = 0x1FFF;

// Where layer 3 starts and what it is.
struct L2Info {
  std::uint16_t ethertype = 0;
  std::uint32_t l3_offset = 0;
  bool has_vlan = false;
  std::uint16_t vlan_id = 0;
};

ParseStatus parse_ethernet(ByteView frame, L2Info& out) noexcept {
  // dst MAC(6) src MAC(6) ethertype(2)
  if (frame.size() < kEthernetHeaderLen) {
    return ParseStatus::TruncatedEthernet;
  }
  out.ethertype = load_be16(frame, 12);
  out.l3_offset = kEthernetHeaderLen;

  if (out.ethertype == ethertype::kVlan) {
    // 802.1Q tag: TCI(2) then the real ethertype(2). Only one tag is
    // supported; a second (QinQ) tag leaves ethertype == 0x8100 and the
    // frame is carried through as non-IP.
    if (frame.size() < kEthernetHeaderLen + kVlanTagLen) {
      return ParseStatus::TruncatedVlan;
    }
    out.has_vlan = true;
    out.vlan_id = load_be16(frame, 14) & 0x0FFF;
    out.ethertype = load_be16(frame, 16);
    out.l3_offset += kVlanTagLen;
  }
  return ParseStatus::Ok;
}

// Decodes the IPv4 header at out.l3_offset. On success, `ip_end` is the
// offset one past the last captured byte that belongs to the IP packet;
// anything after it (e.g. Ethernet padding) is ignored.
ParseStatus parse_ipv4(ByteView frame, bool capture_truncated, ParsedPacket& out,
                       std::size_t& ip_end) noexcept {
  const ByteView ip = frame.subspan(out.l3_offset);
  if (ip.size() < kIpv4MinHeaderLen) {
    return ParseStatus::TruncatedIpv4;
  }

  const std::uint8_t version_ihl = load_u8(ip, 0);
  if ((version_ihl >> 4) != 4) {
    return ParseStatus::BadIpVersion;
  }
  const std::size_t header_len = (version_ihl & 0x0Fu) * 4u;
  if (header_len < kIpv4MinHeaderLen) {
    return ParseStatus::BadIpHeaderLength;
  }
  if (header_len > ip.size()) {
    return ParseStatus::TruncatedIpv4;  // options extend past the capture
  }

  const std::uint16_t total_len = load_be16(ip, 2);
  if (total_len < header_len) {
    return ParseStatus::BadIpTotalLength;
  }
  std::size_t captured_len = total_len;
  if (total_len > ip.size()) {
    // Fewer bytes than the header claims. Legitimate only if snaplen cut
    // the capture; otherwise the length field is lying.
    if (!capture_truncated) {
      return ParseStatus::BadIpTotalLength;
    }
    out.payload_truncated = true;
    captured_len = ip.size();
  }

  const std::uint16_t flags_fragment = load_be16(ip, 6);
  out.more_fragments = (flags_fragment & kIpMoreFragments) != 0;
  out.fragment_offset = static_cast<std::uint16_t>((flags_fragment & kIpFragmentOffsetMask) * 8u);
  out.is_fragment = out.more_fragments || out.fragment_offset != 0;

  out.l3 = L3Kind::Ipv4;
  out.ip_header_len = static_cast<std::uint16_t>(header_len);
  out.ip_total_len = total_len;
  out.ttl = load_u8(ip, 8);
  out.protocol = load_u8(ip, 9);
  out.src_ip = load_be32(ip, 12);
  out.dst_ip = load_be32(ip, 16);
  // The header checksum is deliberately not verified: captures taken on
  // hosts with checksum offload routinely contain "bad" checksums, and a
  // passive inspector should not drop traffic the network delivered.

  out.l4_offset = static_cast<std::uint32_t>(out.l3_offset + header_len);
  ip_end = out.l3_offset + captured_len;
  return ParseStatus::Ok;
}

ParseStatus parse_tcp(ByteView frame, std::size_t ip_end, ParsedPacket& out) noexcept {
  const ByteView segment = frame.subspan(out.l4_offset, ip_end - out.l4_offset);
  const std::size_t claimed_len = out.ip_total_len - out.ip_header_len;
  if (segment.size() < kTcpMinHeaderLen) {
    // Covers both a cut capture and a "tiny fragment" whose IP payload is
    // too small to hold a TCP header (an old firewall-evasion trick).
    return ParseStatus::TruncatedTcp;
  }

  const std::size_t header_len = (load_u8(segment, 12) >> 4) * 4u;
  if (header_len < kTcpMinHeaderLen || header_len > claimed_len) {
    return ParseStatus::BadTcpDataOffset;
  }
  if (header_len > segment.size()) {
    return ParseStatus::TruncatedTcp;  // options cut off by snaplen
  }

  out.l4 = L4Kind::Tcp;
  out.src_port = load_be16(segment, 0);
  out.dst_port = load_be16(segment, 2);
  out.tcp_seq = load_be32(segment, 4);
  out.tcp_flags = load_u8(segment, 13);
  out.tcp_header_len = static_cast<std::uint16_t>(header_len);
  out.payload_offset = static_cast<std::uint32_t>(out.l4_offset + header_len);
  out.payload_len = static_cast<std::uint32_t>(segment.size() - header_len);
  return ParseStatus::Ok;
}

ParseStatus parse_udp(ByteView frame, std::size_t ip_end, ParsedPacket& out) noexcept {
  const ByteView datagram = frame.subspan(out.l4_offset, ip_end - out.l4_offset);
  const std::size_t claimed_len = out.ip_total_len - out.ip_header_len;
  if (datagram.size() < kUdpHeaderLen) {
    return ParseStatus::TruncatedUdp;
  }

  const std::size_t udp_len = load_be16(datagram, 4);
  if (udp_len < kUdpHeaderLen) {
    return ParseStatus::BadUdpLength;
  }
  // In a first fragment the UDP length describes the whole reassembled
  // datagram, so it may legitimately exceed this fragment.
  if (!out.more_fragments && udp_len > claimed_len) {
    return ParseStatus::BadUdpLength;
  }

  out.l4 = L4Kind::Udp;
  out.src_port = load_be16(datagram, 0);
  out.dst_port = load_be16(datagram, 2);
  out.payload_offset = static_cast<std::uint32_t>(out.l4_offset + kUdpHeaderLen);
  const std::size_t end = out.more_fragments ? datagram.size() : std::min(udp_len, datagram.size());
  out.payload_len = static_cast<std::uint32_t>(end - kUdpHeaderLen);
  return ParseStatus::Ok;
}

}  // namespace

const char* to_string(ParseStatus status) noexcept {
  switch (status) {
    case ParseStatus::Ok: return "ok";
    case ParseStatus::TruncatedEthernet: return "truncated_ethernet";
    case ParseStatus::TruncatedVlan: return "truncated_vlan";
    case ParseStatus::TruncatedIpv4: return "truncated_ipv4";
    case ParseStatus::BadIpVersion: return "bad_ip_version";
    case ParseStatus::BadIpHeaderLength: return "bad_ip_header_length";
    case ParseStatus::BadIpTotalLength: return "bad_ip_total_length";
    case ParseStatus::TruncatedTcp: return "truncated_tcp";
    case ParseStatus::BadTcpDataOffset: return "bad_tcp_data_offset";
    case ParseStatus::TruncatedUdp: return "truncated_udp";
    case ParseStatus::BadUdpLength: return "bad_udp_length";
  }
  return "unknown";
}

ParseStatus parse_packet(ByteView frame, std::uint32_t wire_len, ParsedPacket& out) {
  out = ParsedPacket{};

  L2Info l2;
  if (const ParseStatus s = parse_ethernet(frame, l2); s != ParseStatus::Ok) {
    return s;
  }
  out.ethertype = l2.ethertype;
  out.has_vlan = l2.has_vlan;
  out.vlan_id = l2.vlan_id;
  out.l3_offset = l2.l3_offset;

  if (l2.ethertype != ethertype::kIpv4) {
    // Well-formed but outside what we inspect (ARP, IPv6, ...).
    out.payload_offset = l2.l3_offset;
    out.payload_len = static_cast<std::uint32_t>(frame.size() - l2.l3_offset);
    return ParseStatus::Ok;
  }

  const bool capture_truncated = frame.size() < wire_len;
  std::size_t ip_end = 0;
  if (const ParseStatus s = parse_ipv4(frame, capture_truncated, out, ip_end); s != ParseStatus::Ok) {
    return s;
  }

  // Only the first fragment (offset 0) carries the transport header; later
  // fragments are opaque IP payload.
  if (out.fragment_offset == 0) {
    if (out.protocol == ipproto::kTcp) {
      return parse_tcp(frame, ip_end, out);
    }
    if (out.protocol == ipproto::kUdp) {
      return parse_udp(frame, ip_end, out);
    }
    out.l4 = L4Kind::Other;
  }
  out.payload_offset = out.l4_offset;
  out.payload_len = static_cast<std::uint32_t>(ip_end - out.l4_offset);
  return ParseStatus::Ok;
}

std::optional<PacketTuple> peek_tuple(ByteView frame) noexcept {
  L2Info l2;
  if (parse_ethernet(frame, l2) != ParseStatus::Ok || l2.ethertype != ethertype::kIpv4) {
    return std::nullopt;
  }
  const ByteView ip = frame.subspan(l2.l3_offset);
  if (ip.size() < kIpv4MinHeaderLen || (load_u8(ip, 0) >> 4) != 4) {
    return std::nullopt;
  }
  const std::size_t header_len = (load_u8(ip, 0) & 0x0Fu) * 4u;
  if (header_len < kIpv4MinHeaderLen || header_len > ip.size()) {
    return std::nullopt;
  }

  PacketTuple t;
  t.protocol = load_u8(ip, 9);
  t.src_ip = load_be32(ip, 12);
  t.dst_ip = load_be32(ip, 16);

  const bool first_fragment = (load_be16(ip, 6) & kIpFragmentOffsetMask) == 0;
  const bool has_ports = t.protocol == ipproto::kTcp || t.protocol == ipproto::kUdp;
  // TCP and UDP both start with src_port(2) dst_port(2).
  if (first_fragment && has_ports && ip.size() >= header_len + 4) {
    t.src_port = load_be16(ip, header_len);
    t.dst_port = load_be16(ip, header_len + 2);
  }
  return t;
}

}  // namespace dpi
