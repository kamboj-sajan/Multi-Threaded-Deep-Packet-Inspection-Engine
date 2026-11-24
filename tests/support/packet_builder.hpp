#pragma once

// Builds Ethernet/IPv4/TCP|UDP frames byte by byte for tests. Every field
// that a parser validates can be overridden, so tests can produce exactly
// the malformation they want to check.

#include <cstdint>
#include <optional>
#include <vector>

namespace dpi::test {

using Bytes = std::vector<std::uint8_t>;

constexpr std::uint32_t ip(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
  return (std::uint32_t{a} << 24) | (std::uint32_t{b} << 16) | (std::uint32_t{c} << 8) | d;
}

struct FrameSpec {
  // Layer 2
  std::optional<std::uint16_t> vlan_id;
  std::uint16_t ethertype = 0x0800;

  // Layer 3
  std::uint8_t ip_version = 4;
  std::optional<std::uint8_t> ihl_words;          // default: from options
  std::optional<std::uint16_t> ip_total_len;      // default: computed
  Bytes ip_options;                               // multiple of 4 bytes
  std::uint16_t flags_fragment = 0;               // raw flags + offset field
  std::uint8_t protocol = 6;
  std::uint32_t src_ip = ip(10, 0, 0, 1);
  std::uint32_t dst_ip = ip(10, 0, 0, 2);

  // Layer 4
  std::uint16_t src_port = 40000;
  std::uint16_t dst_port = 443;
  std::uint8_t tcp_flags = 0x18;                  // PSH|ACK
  std::uint32_t tcp_seq = 1000;
  std::optional<std::uint8_t> tcp_data_offset_words;
  Bytes tcp_options;                              // multiple of 4 bytes
  std::optional<std::uint16_t> udp_len;

  Bytes payload;
  std::size_t pad_to = 0;  // append zero padding up to this frame size
};

inline void put8(Bytes& b, std::uint8_t v) { b.push_back(v); }
inline void put16(Bytes& b, std::uint16_t v) {
  b.push_back(static_cast<std::uint8_t>(v >> 8));
  b.push_back(static_cast<std::uint8_t>(v));
}
inline void put32(Bytes& b, std::uint32_t v) {
  put16(b, static_cast<std::uint16_t>(v >> 16));
  put16(b, static_cast<std::uint16_t>(v));
}

inline std::uint16_t ipv4_checksum(const Bytes& b, std::size_t offset, std::size_t len) {
  std::uint32_t sum = 0;
  for (std::size_t i = 0; i + 1 < len; i += 2) {
    sum += static_cast<std::uint32_t>((b[offset + i] << 8) | b[offset + i + 1]);
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  return static_cast<std::uint16_t>(~sum);
}

inline Bytes build_l4(const FrameSpec& s) {
  Bytes l4;
  if (s.protocol == 6) {
    const auto offset_words = s.tcp_data_offset_words.value_or(
        static_cast<std::uint8_t>(5 + s.tcp_options.size() / 4));
    put16(l4, s.src_port);
    put16(l4, s.dst_port);
    put32(l4, s.tcp_seq);
    put32(l4, 0);                                   // ack
    put8(l4, static_cast<std::uint8_t>(offset_words << 4));
    put8(l4, s.tcp_flags);
    put16(l4, 65535);                               // window
    put16(l4, 0);                                   // checksum (unchecked)
    put16(l4, 0);                                   // urgent pointer
    l4.insert(l4.end(), s.tcp_options.begin(), s.tcp_options.end());
  } else if (s.protocol == 17) {
    put16(l4, s.src_port);
    put16(l4, s.dst_port);
    put16(l4, s.udp_len.value_or(static_cast<std::uint16_t>(8 + s.payload.size())));
    put16(l4, 0);                                   // checksum optional in IPv4
  }
  l4.insert(l4.end(), s.payload.begin(), s.payload.end());
  return l4;
}

inline Bytes build_frame(const FrameSpec& s) {
  Bytes f;
  // Ethernet: fixed MACs, they never matter to the parser.
  for (int i = 0; i < 6; ++i) put8(f, 0x02);
  for (int i = 0; i < 6; ++i) put8(f, 0x04);
  if (s.vlan_id) {
    put16(f, 0x8100);
    put16(f, *s.vlan_id);
  }
  put16(f, s.ethertype);
  if (s.ethertype != 0x0800) {
    f.insert(f.end(), s.payload.begin(), s.payload.end());
    return f;
  }

  const bool is_later_fragment = (s.flags_fragment & 0x1FFF) != 0;
  const Bytes l4 = is_later_fragment ? s.payload : build_l4(s);
  const std::size_t ip_start = f.size();
  const auto ihl = s.ihl_words.value_or(static_cast<std::uint8_t>(5 + s.ip_options.size() / 4));
  const auto header_bytes = 20 + s.ip_options.size();
  const auto total = s.ip_total_len.value_or(static_cast<std::uint16_t>(header_bytes + l4.size()));

  put8(f, static_cast<std::uint8_t>((s.ip_version << 4) | (ihl & 0x0F)));
  put8(f, 0);              // DSCP/ECN
  put16(f, total);
  put16(f, 0x1234);        // identification
  put16(f, s.flags_fragment);
  put8(f, 64);             // TTL
  put8(f, s.protocol);
  put16(f, 0);             // checksum, filled below
  put32(f, s.src_ip);
  put32(f, s.dst_ip);
  f.insert(f.end(), s.ip_options.begin(), s.ip_options.end());
  const std::uint16_t csum = ipv4_checksum(f, ip_start, header_bytes);
  f[ip_start + 10] = static_cast<std::uint8_t>(csum >> 8);
  f[ip_start + 11] = static_cast<std::uint8_t>(csum);

  f.insert(f.end(), l4.begin(), l4.end());
  if (f.size() < s.pad_to) {
    f.resize(s.pad_to, 0);
  }
  return f;
}

inline FrameSpec tcp_spec(Bytes payload = {}) {
  FrameSpec s;
  s.protocol = 6;
  s.payload = std::move(payload);
  return s;
}

inline FrameSpec udp_spec(Bytes payload = {}) {
  FrameSpec s;
  s.protocol = 17;
  s.dst_port = 53;
  s.payload = std::move(payload);
  return s;
}

}  // namespace dpi::test
