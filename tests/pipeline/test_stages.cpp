#include <gtest/gtest.h>

#include <memory>
#include <set>
#include <utility>
#include <vector>

#include "dpi/pipeline/engine.hpp"
#include "dpi/pipeline/stages.hpp"
#include "pcap_builder.hpp"

namespace dpi {
namespace {

using test::build_frame;
using test::build_pcap;
using test::Bytes;
using test::FrameSpec;
using test::tcp_frame;
using test::TimedFrame;

constexpr std::uint8_t kSyn = tcpflag::kSyn;
constexpr std::uint8_t kSynAck = tcpflag::kSyn | tcpflag::kAck;
constexpr std::uint8_t kAck = tcpflag::kAck;
constexpr std::uint8_t kRst = tcpflag::kRst;

Bytes arp_frame() {
  FrameSpec s;
  s.ethertype = ethertype::kArp;
  s.payload = Bytes(28, 0);
  return build_frame(s);
}

Bytes bad_ihl_frame() {
  FrameSpec s = test::tcp_spec();
  s.ihl_words = 3;
  return build_frame(s);
}

Packet packet_of(Bytes frame, std::uint64_t ts = 0) {
  Packet p;
  p.ts_ns = ts;
  p.orig_len = static_cast<std::uint32_t>(frame.size());
  p.bytes = std::move(frame);
  return p;
}

struct Parsed {
  Packet packet;
  ParsedPacket parsed;
};

Parsed parsed_of(Bytes frame, std::uint64_t ts = 0) {
  Parsed p{packet_of(std::move(frame), ts), {}};
  EXPECT_EQ(parse_packet(p.packet.data(), p.parsed), ParseStatus::Ok);
  return p;
}

TEST(Routing, HashIsDirectionIndependentAndZeroWithoutIpv4) {
  EXPECT_EQ(routing_hash(tcp_frame(true, kAck)), routing_hash(tcp_frame(false, kAck)));
  EXPECT_NE(routing_hash(tcp_frame(true, kAck)), routing_hash(tcp_frame(true, kAck, {}, 40001)));
  EXPECT_EQ(routing_hash(arp_frame()), 0u);
}

TEST(Routing, LbAndFpIndicesUseDifferentHashBits) {
  // With 2 LBs x 2 FPs, hashes 0..3 must cover all four (lb, fp) pairs.
  std::set<std::pair<std::size_t, std::size_t>> seen;
  for (std::uint64_t h = 0; h < 4; ++h) {
    seen.insert({lb_index(h, 2), fp_index_in_group(h, 2, 2)});
  }
  EXPECT_EQ(seen.size(), 4u);
}

TEST(LoadBalancerStage, PassesValidPacketsAndCountsMalformedOnes) {
  LoadBalancerStage lb;
  auto ok = lb.process(RoutedPacket{packet_of(tcp_frame(true, kSyn)), 42});
  ASSERT_TRUE(ok.has_value());
  EXPECT_EQ(ok->hash, 42u);
  EXPECT_EQ(ok->parsed.dst_port, 443);
  EXPECT_FALSE(ok->packet.bytes.empty());

  EXPECT_FALSE(lb.process(RoutedPacket{packet_of(bad_ihl_frame()), 0}).has_value());
  EXPECT_FALSE(lb.process(RoutedPacket{packet_of(Bytes(5, 0)), 0}).has_value());

  EXPECT_EQ(lb.stats().packets, 3u);
  EXPECT_EQ(lb.stats().malformed, 2u);
  EXPECT_EQ(lb.stats().malformed_by_reason[static_cast<std::size_t>(ParseStatus::BadIpHeaderLength)], 1u);
  EXPECT_EQ(lb.stats().malformed_by_reason[static_cast<std::size_t>(ParseStatus::TruncatedEthernet)], 1u);
}

TEST(FastPathStage, TracksBothDirectionsAsOneFlow) {
  FastPathStage fp;
  for (const auto& [from_client, flags] :
       std::vector<std::pair<bool, std::uint8_t>>{{true, kSyn}, {false, kSynAck}, {true, kAck}}) {
    Parsed p = parsed_of(tcp_frame(from_client, flags));
    EXPECT_EQ(fp.process(p.packet, p.parsed), Verdict::Forward);
  }
  Parsed arp = parsed_of(arp_frame());
  EXPECT_EQ(fp.process(arp.packet, arp.parsed), Verdict::Forward);
  fp.finish();

  EXPECT_EQ(fp.stats().packets, 4u);
  EXPECT_EQ(fp.stats().forwarded, 4u);
  EXPECT_EQ(fp.stats().non_ip, 1u);
  EXPECT_EQ(fp.stats().flows_created, 1u);
  // No payload yet, so the port-based guess (443 -> HTTPS) stands.
  EXPECT_EQ(fp.stats().apps[static_cast<std::size_t>(AppId::HTTPS)].flows, 1u);
  EXPECT_EQ(fp.stats().apps[static_cast<std::size_t>(AppId::HTTPS)].packets, 3u);
}

TEST(FastPathStage, SynAfterResetStartsANewFlow) {
  FastPathStage fp;
  for (const auto& [from_client, flags] : std::vector<std::pair<bool, std::uint8_t>>{
           {true, kSyn}, {false, kRst}, {true, kSyn}, {false, kSynAck}}) {
    Parsed p = parsed_of(tcp_frame(from_client, flags));
    fp.process(p.packet, p.parsed);
  }
  fp.finish();
  EXPECT_EQ(fp.stats().flows_created, 2u);
  EXPECT_EQ(fp.stats().apps[static_cast<std::size_t>(AppId::HTTPS)].packets, 4u);  // 2 + 2
}

TEST(FastPathStage, IdleGapSplitsAFlow) {
  FastPathConfig config;
  config.flow_table.idle_timeout_ns = 5'000'000'000ULL;
  FastPathStage fp(config);
  Parsed a = parsed_of(tcp_frame(true, kAck), 0);
  Parsed b = parsed_of(tcp_frame(true, kAck), 6'000'000'000ULL);
  fp.process(a.packet, a.parsed);
  fp.process(b.packet, b.parsed);
  fp.finish();
  EXPECT_EQ(fp.stats().flows_created, 2u);
  EXPECT_EQ(fp.stats().flows_expired, 1u);
}

TEST(Sequential, EndToEndAccountingAndOrder) {
  std::vector<TimedFrame> frames = {
      {1, tcp_frame(true, kSyn)},      {2, tcp_frame(false, kSynAck)}, {3, bad_ihl_frame()},
      {4, tcp_frame(true, kAck)},      {5, arp_frame()},               {6, Bytes(9, 0xff)},
      {7, tcp_frame(true, kAck, Bytes(100, 1), 40001)},
  };
  Bytes input = build_pcap(frames);
  // Append a record header that promises more bytes than the file holds.
  const Bytes truncated_tail(10, 0);
  input.insert(input.end(), truncated_tail.begin(), truncated_tail.end());

  Bytes output;
  PcapReader reader(std::make_unique<MemorySource>(input));
  PcapWriter writer(std::make_unique<MemorySink>(output), {.precision = pcap::Precision::Nano});
  const RunStats stats = run_sequential(reader, writer, EngineConfig{});

  EXPECT_EQ(stats.total_packets(), 8u);
  EXPECT_EQ(stats.malformed(), 3u);  // bad IHL, 9-byte frame, truncated record
  EXPECT_EQ(stats.forwarded(), 5u);
  EXPECT_EQ(stats.dropped(), 0u);
  EXPECT_EQ(stats.total_packets(), stats.forwarded() + stats.dropped() + stats.malformed());
  EXPECT_EQ(stats.reader.truncated_records, 1u);
  EXPECT_EQ(stats.merged_fast_path().flows_created, 2u);
  EXPECT_EQ(stats.merged_fast_path().non_ip, 1u);
  EXPECT_EQ(stats.writer.packets, 5u);

  // The output holds exactly the forwarded packets, in input order.
  PcapReader out_reader(std::make_unique<MemorySource>(output));
  std::vector<std::uint64_t> timestamps;
  Packet p;
  while (out_reader.next(p) == ReadStatus::Ok) {
    timestamps.push_back(p.ts_ns);
  }
  EXPECT_EQ(timestamps, (std::vector<std::uint64_t>{1, 2, 4, 5, 7}));
}

TEST(Stats, TopSnisSortsByCountThenName) {
  FpStats stats;
  stats.sni_flows = {{"b.com", 3}, {"a.com", 3}, {"c.com", 5}, {"d.com", 1}};
  const auto top = top_snis(stats, 3);
  ASSERT_EQ(top.size(), 3u);
  EXPECT_EQ(top[0].sni, "c.com");
  EXPECT_EQ(top[1].sni, "a.com");
  EXPECT_EQ(top[2].sni, "b.com");
}

TEST(Stats, MergeAddsEveryCounter) {
  FpStats a;
  a.packets = 1;
  a.apps[3].flows = 2;
  a.sni_flows["x"] = 1;
  FpStats b;
  b.packets = 2;
  b.apps[3].flows = 5;
  b.sni_flows["x"] = 4;
  b.sni_flows["y"] = 1;
  a.merge(b);
  EXPECT_EQ(a.packets, 3u);
  EXPECT_EQ(a.apps[3].flows, 7u);
  EXPECT_EQ(a.sni_flows["x"], 5u);
  EXPECT_EQ(a.sni_flows["y"], 1u);
}

}  // namespace
}  // namespace dpi
