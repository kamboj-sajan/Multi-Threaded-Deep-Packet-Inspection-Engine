// Blocking with rules/example_rules.txt on the generated captures:
//   block ip 192.168.1.50 / block domain *.tiktok.com /
//   block app YouTube / block port 6881
// Expected numbers are the "With rules/example_rules.txt" sections of
// tests/data/MANIFEST.md, computed by the generator's own rule model.

#include <gtest/gtest.h>

#include <map>
#include <set>

#include "dpi/flow/five_tuple.hpp"
#include "dpi/parser/packet_parser.hpp"
#include "run_helpers.hpp"
#include "packet_builder.hpp"

namespace dpi {
namespace {

using test::read_all;
using test::run_file_sequential;
using test::with_example_rules;

std::uint64_t blocked_by(const FpStats& fp, BlockReason r) {
  return fp.flows_blocked_by_reason[static_cast<std::size_t>(r)];
}

TEST(Blocking, MixedCaptureCounts) {
  const RunStats s = run_file_sequential("mixed.pcap", with_example_rules()).stats;
  EXPECT_EQ(s.total_packets(), 254u);
  EXPECT_EQ(s.dropped(), 59u);
  EXPECT_EQ(s.forwarded(), 185u);
  EXPECT_EQ(s.malformed(), 10u);
  EXPECT_EQ(s.writer.packets, 185u);
  const FpStats fp = s.merged_fast_path();
  EXPECT_EQ(fp.flows_blocked, 7u);
  EXPECT_EQ(blocked_by(fp, BlockReason::Ip), 2u);      // the two flows of 192.168.1.50
  EXPECT_EQ(blocked_by(fp, BlockReason::Port), 1u);    // BitTorrent on 6881
  EXPECT_EQ(blocked_by(fp, BlockReason::App), 3u);     // three YouTube flows
  EXPECT_EQ(blocked_by(fp, BlockReason::Domain), 1u);  // www.tiktok.com
  // Classification is unaffected by blocking.
  EXPECT_EQ(fp.apps[static_cast<std::size_t>(AppId::YouTube)].flows, 3u);
}

TEST(Blocking, OtherCaptures) {
  const RunStats many = run_file_sequential("many_flows.pcap", with_example_rules()).stats;
  EXPECT_EQ(many.dropped(), 1269u);
  EXPECT_EQ(many.forwarded(), 7731u);
  EXPECT_EQ(blocked_by(many.merged_fast_path(), BlockReason::App), 141u);

  const RunStats split = run_file_sequential("tls_split.pcap", with_example_rules()).stats;
  EXPECT_EQ(split.dropped(), 7u);  // YouTube hello in 2 segments: dropped from the 2nd
  EXPECT_EQ(split.forwarded(), 43u);

  const RunStats malformed = run_file_sequential("malformed.pcap", with_example_rules()).stats;
  EXPECT_EQ(malformed.dropped(), 0u);
}

TEST(Blocking, OutputContainsNothingFromIpOrPortBlockedFlows) {
  const auto run = run_file_sequential("mixed.pcap", with_example_rules());
  for (const Packet& p : read_all(run.pcap)) {
    const auto t = peek_tuple(p.data());
    if (!t) {
      continue;
    }
    EXPECT_NE(t->src_ip, test::ip(192, 168, 1, 50));
    EXPECT_NE(t->dst_ip, test::ip(192, 168, 1, 50));
    EXPECT_NE(t->src_port, 6881);
    EXPECT_NE(t->dst_port, 6881);
  }
}

TEST(Blocking, DomainAndAppBlockedFlowsKeepOnlyTheirHandshake) {
  // Servers of the YouTube and TikTok flows in mixed.pcap.
  const std::set<std::uint32_t> blocked_servers = {
      test::ip(142, 250, 72, 14), test::ip(173, 194, 55, 6), test::ip(23, 40, 44, 10)};
  const auto run = run_file_sequential("mixed.pcap", with_example_rules());

  std::map<std::uint16_t, int> packets_per_client_port;
  for (const Packet& p : read_all(run.pcap)) {
    ParsedPacket parsed;
    ASSERT_EQ(parse_packet(p.data(), p.orig_len, parsed), ParseStatus::Ok);
    const bool to_server = blocked_servers.contains(parsed.dst_ip);
    const bool from_server = blocked_servers.contains(parsed.src_ip);
    if (!to_server && !from_server) {
      continue;
    }
    // Only SYN, SYN-ACK and ACK made it out: no payload at all.
    EXPECT_EQ(parsed.payload_len, 0u);
    ++packets_per_client_port[to_server ? parsed.src_port : parsed.dst_port];
  }
  EXPECT_EQ(packets_per_client_port, (std::map<std::uint16_t, int>{{50001, 3}, {50002, 3}, {50003, 3}, {50012, 3}}));
}

}  // namespace
}  // namespace dpi
