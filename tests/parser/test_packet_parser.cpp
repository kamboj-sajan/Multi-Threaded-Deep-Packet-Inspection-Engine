#include <gtest/gtest.h>

#include <algorithm>
#include <random>
#include <string>
#include <vector>

#include "dpi/parser/packet_parser.hpp"
#include "packet_builder.hpp"

namespace dpi {
namespace {

using test::build_frame;
using test::Bytes;
using test::FrameSpec;
using test::ip;
using test::tcp_spec;
using test::udp_spec;

constexpr std::uint32_t kEth = 14;
constexpr std::uint32_t kIp = 20;
constexpr std::uint32_t kTcp = 20;
constexpr std::uint32_t kUdp = 8;

ParseStatus parse(const Bytes& frame, ParsedPacket& out) { return parse_packet(frame, out); }

Bytes bytes_of(const std::string& s) { return Bytes(s.begin(), s.end()); }

// Copies the first `len` bytes into their own allocation. Parsing a prefix
// view of a longer buffer would hide over-reads from AddressSanitizer;
// an exact-size heap buffer makes any over-read a hard failure.
Bytes prefix(const Bytes& frame, std::size_t len) {
  return Bytes(frame.begin(), frame.begin() + static_cast<std::ptrdiff_t>(len));
}

// --- valid packets --------------------------------------------------------

TEST(PacketParser, ParsesTcpOverIpv4) {
  FrameSpec spec = tcp_spec(bytes_of("hello"));
  spec.src_ip = ip(192, 168, 1, 10);
  spec.dst_ip = ip(93, 184, 216, 34);
  spec.src_port = 51000;
  spec.dst_port = 443;
  spec.tcp_flags = tcpflag::kSyn;
  spec.tcp_seq = 0xdeadbeef;
  const Bytes frame = build_frame(spec);

  ParsedPacket p;
  ASSERT_EQ(parse(frame, p), ParseStatus::Ok);
  EXPECT_EQ(p.ethertype, ethertype::kIpv4);
  EXPECT_FALSE(p.has_vlan);
  EXPECT_EQ(p.l3, L3Kind::Ipv4);
  EXPECT_EQ(p.l3_offset, kEth);
  EXPECT_EQ(p.src_ip, ip(192, 168, 1, 10));
  EXPECT_EQ(p.dst_ip, ip(93, 184, 216, 34));
  EXPECT_EQ(p.protocol, ipproto::kTcp);
  EXPECT_EQ(p.ttl, 64);
  EXPECT_FALSE(p.is_fragment);
  EXPECT_EQ(p.l4, L4Kind::Tcp);
  EXPECT_EQ(p.l4_offset, kEth + kIp);
  EXPECT_EQ(p.src_port, 51000);
  EXPECT_EQ(p.dst_port, 443);
  EXPECT_EQ(p.tcp_flags, tcpflag::kSyn);
  EXPECT_EQ(p.tcp_seq, 0xdeadbeefu);
  EXPECT_EQ(p.tcp_header_len, kTcp);
  EXPECT_EQ(p.payload_offset, kEth + kIp + kTcp);
  EXPECT_EQ(p.payload_len, 5u);
  EXPECT_FALSE(p.payload_truncated);
  const ByteView payload = p.payload(frame);
  EXPECT_EQ(std::string(payload.begin(), payload.end()), "hello");
}

TEST(PacketParser, ParsesUdpOverIpv4) {
  FrameSpec spec = udp_spec(bytes_of("dnsquery"));
  spec.src_port = 5353;
  spec.dst_port = 53;
  const Bytes frame = build_frame(spec);

  ParsedPacket p;
  ASSERT_EQ(parse(frame, p), ParseStatus::Ok);
  EXPECT_EQ(p.l4, L4Kind::Udp);
  EXPECT_EQ(p.src_port, 5353);
  EXPECT_EQ(p.dst_port, 53);
  EXPECT_EQ(p.payload_offset, kEth + kIp + kUdp);
  EXPECT_EQ(p.payload_len, 8u);
}

TEST(PacketParser, ParsesVlanTaggedFrame) {
  FrameSpec spec = tcp_spec(bytes_of("x"));
  spec.vlan_id = 0x2064;  // PCP bits set, VID 0x064
  const Bytes frame = build_frame(spec);

  ParsedPacket p;
  ASSERT_EQ(parse(frame, p), ParseStatus::Ok);
  EXPECT_TRUE(p.has_vlan);
  EXPECT_EQ(p.vlan_id, 0x064);  // priority bits are masked off
  EXPECT_EQ(p.ethertype, ethertype::kIpv4);
  EXPECT_EQ(p.l3_offset, kEth + 4);
  EXPECT_EQ(p.payload_offset, kEth + 4 + kIp + kTcp);
  EXPECT_EQ(p.payload_len, 1u);
}

TEST(PacketParser, IpOptionsMoveTheTransportHeader) {
  FrameSpec spec = tcp_spec(bytes_of("data"));
  spec.ip_options = {0x01, 0x01, 0x01, 0x00, 0x01, 0x01, 0x01, 0x00};  // NOPs + EOL
  const Bytes frame = build_frame(spec);

  ParsedPacket p;
  ASSERT_EQ(parse(frame, p), ParseStatus::Ok);
  EXPECT_EQ(p.ip_header_len, 28);
  EXPECT_EQ(p.l4_offset, kEth + 28);
  EXPECT_EQ(p.dst_port, 443);
  EXPECT_EQ(p.payload_len, 4u);
}

TEST(PacketParser, TcpOptionsMoveThePayload) {
  FrameSpec spec = tcp_spec(bytes_of("abc"));
  spec.tcp_options = {0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02};  // MSS, NOP, NOP, SACK-ok
  const Bytes frame = build_frame(spec);

  ParsedPacket p;
  ASSERT_EQ(parse(frame, p), ParseStatus::Ok);
  EXPECT_EQ(p.tcp_header_len, 28);
  EXPECT_EQ(p.payload_offset, kEth + kIp + 28);
  EXPECT_EQ(p.payload_len, 3u);
}

TEST(PacketParser, EthernetPaddingIsNotPayload) {
  FrameSpec spec = udp_spec(bytes_of("hi"));
  spec.pad_to = 60;  // minimum Ethernet frame size without FCS
  const Bytes frame = build_frame(spec);
  ASSERT_EQ(frame.size(), 60u);

  ParsedPacket p;
  ASSERT_EQ(parse(frame, p), ParseStatus::Ok);
  EXPECT_EQ(p.payload_len, 2u);
}

TEST(PacketParser, NonIpv4FramesAreAcceptedButNotDecoded) {
  for (const std::uint16_t type : {ethertype::kArp, ethertype::kIpv6}) {
    FrameSpec spec;
    spec.ethertype = type;
    spec.payload = Bytes(28, 0);
    const Bytes frame = build_frame(spec);

    ParsedPacket p;
    ASSERT_EQ(parse(frame, p), ParseStatus::Ok) << "ethertype " << type;
    EXPECT_EQ(p.l3, L3Kind::NonIp);
    EXPECT_EQ(p.ethertype, type);
    EXPECT_EQ(p.l4, L4Kind::None);
    EXPECT_EQ(p.tuple(), PacketTuple{});
  }
}

TEST(PacketParser, OtherIpProtocolsHaveNoPorts) {
  FrameSpec spec;
  spec.protocol = ipproto::kIcmp;
  spec.payload = {8, 0, 0, 0, 0, 1, 0, 1};  // echo request
  const Bytes frame = build_frame(spec);

  ParsedPacket p;
  ASSERT_EQ(parse(frame, p), ParseStatus::Ok);
  EXPECT_EQ(p.l4, L4Kind::Other);
  EXPECT_FALSE(p.has_ports());
  EXPECT_EQ(p.src_port, 0);
  EXPECT_EQ(p.payload_offset, kEth + kIp);
  EXPECT_EQ(p.payload_len, 8u);
}

// --- truncation at every header boundary ----------------------------------

struct Boundary {
  std::size_t up_to;  // exclusive: lengths below this fail with `status`
  ParseStatus status;
};

// Cuts `frame` at every length and checks the expected status. The wire
// length stays at the full size, so each cut looks like a snaplen-truncated
// capture: header cuts are malformed, payload cuts are accepted.
void expect_truncation_boundaries(const Bytes& frame, const std::vector<Boundary>& boundaries) {
  const auto wire_len = static_cast<std::uint32_t>(frame.size());
  for (std::size_t len = 0; len <= frame.size(); ++len) {
    const Bytes cut = prefix(frame, len);
    ParsedPacket p;
    const ParseStatus got = parse_packet(cut, wire_len, p);

    ParseStatus want = ParseStatus::Ok;
    for (const Boundary& b : boundaries) {
      if (len < b.up_to) {
        want = b.status;
        break;
      }
    }
    ASSERT_EQ(got, want) << "cut at " << len << " of " << frame.size();
    if (got == ParseStatus::Ok) {
      EXPECT_EQ(p.payload_offset + p.payload_len, len) << "cut at " << len;
      EXPECT_EQ(p.payload_truncated, len < frame.size());
    }
  }
}

TEST(PacketParser, TcpTruncatedAtEveryLength) {
  const Bytes frame = build_frame(tcp_spec(bytes_of("payload")));
  expect_truncation_boundaries(frame, {{kEth, ParseStatus::TruncatedEthernet},
                                       {kEth + kIp, ParseStatus::TruncatedIpv4},
                                       {kEth + kIp + kTcp, ParseStatus::TruncatedTcp}});
}

TEST(PacketParser, VlanTcpTruncatedAtEveryLength) {
  FrameSpec spec = tcp_spec(bytes_of("payload"));
  spec.vlan_id = 7;
  const Bytes frame = build_frame(spec);
  expect_truncation_boundaries(frame, {{kEth, ParseStatus::TruncatedEthernet},
                                       {kEth + 4, ParseStatus::TruncatedVlan},
                                       {kEth + 4 + kIp, ParseStatus::TruncatedIpv4},
                                       {kEth + 4 + kIp + kTcp, ParseStatus::TruncatedTcp}});
}

TEST(PacketParser, UdpTruncatedAtEveryLength) {
  const Bytes frame = build_frame(udp_spec(bytes_of("payload")));
  expect_truncation_boundaries(frame, {{kEth, ParseStatus::TruncatedEthernet},
                                       {kEth + kIp, ParseStatus::TruncatedIpv4},
                                       {kEth + kIp + kUdp, ParseStatus::TruncatedUdp}});
}

TEST(PacketParser, TruncationInsideIpOptionsIsMalformed) {
  FrameSpec spec = tcp_spec();
  spec.ip_options = Bytes(12, 0x01);
  const Bytes frame = build_frame(spec);
  ParsedPacket p;
  EXPECT_EQ(parse_packet(prefix(frame, kEth + 24), static_cast<std::uint32_t>(frame.size()), p),
            ParseStatus::TruncatedIpv4);
}

TEST(PacketParser, TruncationInsideTcpOptionsIsMalformed) {
  FrameSpec spec = tcp_spec();
  spec.tcp_options = Bytes(12, 0x01);
  const Bytes frame = build_frame(spec);
  ParsedPacket p;
  EXPECT_EQ(parse_packet(prefix(frame, kEth + kIp + 24), static_cast<std::uint32_t>(frame.size()), p),
            ParseStatus::TruncatedTcp);
}

TEST(PacketParser, LengthBeyondCompleteFrameIsMalformed) {
  // caplen == wire length, yet IP claims more bytes than exist: a lie, not
  // a snaplen cut.
  FrameSpec spec = tcp_spec(bytes_of("abc"));
  spec.ip_total_len = 200;
  ParsedPacket p;
  EXPECT_EQ(parse(build_frame(spec), p), ParseStatus::BadIpTotalLength);
}

// --- invalid header fields -----------------------------------------------

TEST(PacketParser, RejectsWrongIpVersion) {
  FrameSpec spec = tcp_spec();
  spec.ip_version = 6;  // with an IPv4 ethertype
  ParsedPacket p;
  EXPECT_EQ(parse(build_frame(spec), p), ParseStatus::BadIpVersion);
}

TEST(PacketParser, RejectsIhlBelowFive) {
  for (std::uint8_t ihl = 0; ihl < 5; ++ihl) {
    FrameSpec spec = tcp_spec();
    spec.ihl_words = ihl;
    ParsedPacket p;
    EXPECT_EQ(parse(build_frame(spec), p), ParseStatus::BadIpHeaderLength) << "ihl " << int{ihl};
  }
}

TEST(PacketParser, RejectsIhlLongerThanPacket) {
  FrameSpec spec;
  spec.protocol = ipproto::kIcmp;
  spec.ihl_words = 15;  // 60-byte header, but only 20 bytes + 0 payload exist
  ParsedPacket p;
  EXPECT_EQ(parse(build_frame(spec), p), ParseStatus::TruncatedIpv4);
}

TEST(PacketParser, RejectsTotalLengthSmallerThanHeader) {
  FrameSpec spec = tcp_spec();
  spec.ip_total_len = 19;
  ParsedPacket p;
  EXPECT_EQ(parse(build_frame(spec), p), ParseStatus::BadIpTotalLength);
}

TEST(PacketParser, RejectsTcpDataOffsetBelowFive) {
  for (std::uint8_t words = 0; words < 5; ++words) {
    FrameSpec spec = tcp_spec(bytes_of("abcdefgh"));
    spec.tcp_data_offset_words = words;
    ParsedPacket p;
    EXPECT_EQ(parse(build_frame(spec), p), ParseStatus::BadTcpDataOffset) << "words " << int{words};
  }
}

TEST(PacketParser, RejectsTcpDataOffsetPastSegment) {
  FrameSpec spec = tcp_spec(bytes_of("ab"));
  spec.tcp_data_offset_words = 15;  // 60 bytes, segment is 22
  ParsedPacket p;
  EXPECT_EQ(parse(build_frame(spec), p), ParseStatus::BadTcpDataOffset);
}

TEST(PacketParser, RejectsBadUdpLength) {
  FrameSpec too_small = udp_spec(bytes_of("abc"));
  too_small.udp_len = 7;
  FrameSpec too_big = udp_spec(bytes_of("abc"));
  too_big.udp_len = 100;
  ParsedPacket p;
  EXPECT_EQ(parse(build_frame(too_small), p), ParseStatus::BadUdpLength);
  EXPECT_EQ(parse(build_frame(too_big), p), ParseStatus::BadUdpLength);
}

TEST(PacketParser, UdpLengthShorterThanIpPayloadLimitsPayload) {
  FrameSpec spec = udp_spec(bytes_of("abcdef"));
  spec.udp_len = 8 + 2;
  ParsedPacket p;
  ASSERT_EQ(parse(build_frame(spec), p), ParseStatus::Ok);
  EXPECT_EQ(p.payload_len, 2u);
}

// --- IP fragments ---------------------------------------------------------

TEST(PacketParser, FirstFragmentCarriesTransportHeader) {
  FrameSpec spec = udp_spec(Bytes(16, 0xab));
  spec.flags_fragment = 0x2000;  // MF, offset 0
  spec.udp_len = 8 + 3000;       // covers the whole reassembled datagram
  ParsedPacket p;
  ASSERT_EQ(parse(build_frame(spec), p), ParseStatus::Ok);
  EXPECT_TRUE(p.is_fragment);
  EXPECT_TRUE(p.more_fragments);
  EXPECT_EQ(p.fragment_offset, 0);
  EXPECT_EQ(p.l4, L4Kind::Udp);
  EXPECT_EQ(p.dst_port, 53);
  EXPECT_EQ(p.payload_len, 16u);  // only what this fragment holds
}

TEST(PacketParser, LaterFragmentsHaveNoTransportHeader) {
  FrameSpec spec = tcp_spec(Bytes(40, 0xcd));
  spec.flags_fragment = 185;  // offset 185*8 = 1480 bytes, last fragment
  ParsedPacket p;
  ASSERT_EQ(parse(build_frame(spec), p), ParseStatus::Ok);
  EXPECT_TRUE(p.is_fragment);
  EXPECT_FALSE(p.more_fragments);
  EXPECT_EQ(p.fragment_offset, 1480);
  EXPECT_EQ(p.l4, L4Kind::None);
  EXPECT_EQ(p.src_port, 0);
  EXPECT_EQ(p.dst_port, 0);
  EXPECT_EQ(p.payload_offset, kEth + kIp);
  EXPECT_EQ(p.payload_len, 40u);
}

TEST(PacketParser, TinyFirstFragmentIsMalformed) {
  // A first fragment too short to hold a full TCP header.
  FrameSpec spec = tcp_spec();
  spec.flags_fragment = 0x2000;
  spec.ip_total_len = kIp + 8;
  Bytes frame = build_frame(spec);
  frame.resize(kEth + kIp + 8);
  ParsedPacket p;
  EXPECT_EQ(parse(frame, p), ParseStatus::TruncatedTcp);
}

// --- peek_tuple -----------------------------------------------------------

TEST(PeekTuple, MatchesFullParseForEveryAcceptedShape) {
  std::vector<FrameSpec> specs;
  specs.push_back(tcp_spec(bytes_of("x")));
  specs.push_back(udp_spec(bytes_of("y")));
  FrameSpec vlan = tcp_spec();
  vlan.vlan_id = 42;
  specs.push_back(vlan);
  FrameSpec options = udp_spec();
  options.ip_options = Bytes(8, 0x01);
  specs.push_back(options);
  FrameSpec first_frag = tcp_spec(Bytes(20, 1));
  first_frag.flags_fragment = 0x2000;
  specs.push_back(first_frag);
  FrameSpec later_frag = tcp_spec(Bytes(20, 1));
  later_frag.flags_fragment = 0x0010;
  specs.push_back(later_frag);
  FrameSpec icmp;
  icmp.protocol = ipproto::kIcmp;
  icmp.payload = Bytes(8, 0);
  specs.push_back(icmp);

  for (std::size_t i = 0; i < specs.size(); ++i) {
    const Bytes frame = build_frame(specs[i]);
    ParsedPacket p;
    ASSERT_EQ(parse(frame, p), ParseStatus::Ok) << "spec " << i;
    const auto peeked = peek_tuple(frame);
    ASSERT_TRUE(peeked.has_value()) << "spec " << i;
    EXPECT_EQ(*peeked, p.tuple()) << "spec " << i;
  }
}

TEST(PeekTuple, ReturnsNulloptForNonIpv4AndGarbage) {
  FrameSpec arp;
  arp.ethertype = ethertype::kArp;
  arp.payload = Bytes(28, 0);
  EXPECT_FALSE(peek_tuple(build_frame(arp)).has_value());
  EXPECT_FALSE(peek_tuple(Bytes{}).has_value());
  EXPECT_FALSE(peek_tuple(prefix(build_frame(tcp_spec()), 20)).has_value());
}

// --- robustness -----------------------------------------------------------

// Mutates a valid frame at random and checks the parser never reports
// offsets outside the buffer. Under ASan this also proves no over-reads.
TEST(PacketParser, SurvivesRandomMutations) {
  std::mt19937 rng(12345);  // fixed seed: failures must be reproducible
  const Bytes base = build_frame(tcp_spec(bytes_of("GET / HTTP/1.1\r\n")));
  for (int iter = 0; iter < 20000; ++iter) {
    Bytes frame = base;
    const int flips = 1 + static_cast<int>(rng() % 6);
    for (int i = 0; i < flips; ++i) {
      frame[rng() % frame.size()] = static_cast<std::uint8_t>(rng());
    }
    frame.resize(rng() % (frame.size() + 1));
    const auto wire_len = static_cast<std::uint32_t>(frame.size() + (rng() % 2) * 100);

    ParsedPacket p;
    if (parse_packet(frame, wire_len, p) == ParseStatus::Ok) {
      ASSERT_LE(p.payload_offset + p.payload_len, frame.size());
      (void)p.payload(frame);
    }
    (void)peek_tuple(frame);
  }
}

TEST(PacketParser, StatusNamesAreDistinct) {
  std::vector<std::string> names;
  for (std::size_t i = 0; i < kParseStatusCount; ++i) {
    names.emplace_back(to_string(static_cast<ParseStatus>(i)));
    EXPECT_NE(names.back(), "unknown");
  }
  std::sort(names.begin(), names.end());
  EXPECT_EQ(std::unique(names.begin(), names.end()), names.end());
}

}  // namespace
}  // namespace dpi
