// End-to-end tests on the captures in tests/data. Every expected number
// comes from tests/data/MANIFEST.md, which tools/gen_pcap.py computes from
// what it generated, independently of this engine.

#include <gtest/gtest.h>

#include "dpi/parser/packet_parser.hpp"
#include "run_helpers.hpp"

namespace dpi {
namespace {

using test::read_all;
using test::read_all_file;
using test::run_file_sequential;

std::uint64_t reason(const RunStats& s, ParseStatus status) {
  return s.malformed_by_reason()[static_cast<std::size_t>(status)];
}

void expect_one_of_each_malformation(const RunStats& s) {
  for (std::size_t i = 1; i < kParseStatusCount; ++i) {
    EXPECT_EQ(reason(s, static_cast<ParseStatus>(i)), 1u) << to_string(static_cast<ParseStatus>(i));
  }
}

TEST(Integration, MixedCaptureCounts) {
  const RunStats s = run_file_sequential("mixed.pcap").stats;
  EXPECT_EQ(s.total_packets(), 254u);
  EXPECT_EQ(s.malformed(), 10u);
  expect_one_of_each_malformation(s);
  EXPECT_EQ(s.forwarded(), 244u);  // 242 valid IPv4 + 2 ARP; no rules loaded
  EXPECT_EQ(s.dropped(), 0u);
  EXPECT_EQ(s.merged_fast_path().non_ip, 2u);
  EXPECT_EQ(s.merged_fast_path().flows_created, 30u);
  EXPECT_EQ(s.writer.packets, 244u);
  EXPECT_EQ(s.reader.truncated_records, 0u);
}

TEST(Integration, MalformedCaptureCounts) {
  const RunStats s = run_file_sequential("malformed.pcap").stats;
  EXPECT_EQ(s.total_packets(), 13u);
  EXPECT_EQ(s.malformed(), 11u);  // 10 bad headers + the cut-off final record
  expect_one_of_each_malformation(s);
  EXPECT_EQ(s.reader.truncated_records, 1u);
  EXPECT_EQ(s.forwarded(), 2u);
  EXPECT_EQ(s.merged_fast_path().flows_created, 1u);
}

TEST(Integration, ManyFlowsCaptureCounts) {
  const RunStats s = run_file_sequential("many_flows.pcap").stats;
  EXPECT_EQ(s.total_packets(), 9000u);
  EXPECT_EQ(s.malformed(), 0u);
  EXPECT_EQ(s.forwarded(), 9000u);
  EXPECT_EQ(s.merged_fast_path().flows_created, 1000u);
}

TEST(Integration, OutputHoldsExactlyTheValidPacketsInOrder) {
  const auto run = run_file_sequential("mixed.pcap");
  const std::vector<Packet> input = read_all_file("mixed.pcap");
  const std::vector<Packet> output = read_all(run.pcap);
  ASSERT_EQ(output.size(), run.stats.forwarded());

  // With no rules, the output is the input minus malformed packets, byte
  // for byte, including the snaplen-truncated packet's original length.
  std::size_t out_index = 0;
  for (const Packet& in : input) {
    ParsedPacket parsed;
    if (parse_packet(in.data(), in.orig_len, parsed) != ParseStatus::Ok) {
      continue;
    }
    ASSERT_LT(out_index, output.size());
    const Packet& out = output[out_index++];
    EXPECT_EQ(out.bytes, in.bytes) << "input record " << in.seq;
    EXPECT_EQ(out.ts_ns, in.ts_ns);
    EXPECT_EQ(out.orig_len, in.orig_len);
  }
  EXPECT_EQ(out_index, output.size());
}

TEST(Integration, StatsInvariantHoldsOnEveryCapture) {
  for (const char* name : {"mixed.pcap", "malformed.pcap", "many_flows.pcap"}) {
    const RunStats s = run_file_sequential(name).stats;
    EXPECT_EQ(s.total_packets(), s.forwarded() + s.dropped() + s.malformed()) << name;
    EXPECT_EQ(s.writer.packets, s.forwarded()) << name;
    std::uint64_t flow_packets = 0;
    const FpStats fp = s.merged_fast_path();
    for (const AppCounters& app : fp.apps) {
      flow_packets += app.packets;
    }
    // Every IPv4 packet the fast path saw belongs to exactly one flow.
    EXPECT_EQ(flow_packets, fp.packets - fp.non_ip) << name;
  }
}

}  // namespace
}  // namespace dpi
