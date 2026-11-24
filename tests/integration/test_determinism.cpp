// The threaded pipeline must reach exactly the same conclusions as the
// single-threaded baseline, whatever the thread layout or queue size.
// Only the interleaving of *different* flows in the output may differ.

#include <gtest/gtest.h>

#include <algorithm>
#include <map>
#include <string>
#include <tuple>
#include <vector>

#include "dpi/flow/five_tuple.hpp"
#include "dpi/parser/packet_parser.hpp"
#include "run_helpers.hpp"

namespace dpi {
namespace {

using test::data_path;
using test::read_all;
using test::RunOutput;
using test::run_file_sequential;

RunOutput run_file_pipeline(const std::string& name, const EngineConfig& config) {
  RunOutput out;
  PcapReader reader = PcapReader::open_file(data_path(name));
  PcapWriter writer(std::make_unique<MemorySink>(out.pcap), {.precision = reader.info().precision});
  out.stats = run_pipeline(reader, writer, config);
  return out;
}

EngineConfig layout(std::size_t lbs, std::size_t fps, std::size_t queue) {
  EngineConfig c;
  c.num_lbs = lbs;
  c.fps_per_lb = fps;
  c.queue_capacity = queue;
  return c;
}

void expect_same_results(const RunStats& want, const RunStats& got) {
  EXPECT_EQ(got.total_packets(), want.total_packets());
  EXPECT_EQ(got.forwarded(), want.forwarded());
  EXPECT_EQ(got.dropped(), want.dropped());
  EXPECT_EQ(got.malformed(), want.malformed());
  EXPECT_EQ(got.malformed_by_reason(), want.malformed_by_reason());
  EXPECT_EQ(got.writer.packets, want.writer.packets);
  EXPECT_EQ(got.writer.bytes, want.writer.bytes);

  const FpStats a = want.merged_fast_path();
  const FpStats b = got.merged_fast_path();
  EXPECT_EQ(b.packets, a.packets);
  EXPECT_EQ(b.bytes, a.bytes);
  EXPECT_EQ(b.non_ip, a.non_ip);
  EXPECT_EQ(b.flows_created, a.flows_created);
  EXPECT_EQ(b.flows_blocked, a.flows_blocked);
  // These captures have no idle gaps, so expiry counts match too. (In
  // general, *when* an idle flow is swept is per-thread timing; the flow
  // boundaries themselves are deterministic either way.)
  EXPECT_EQ(b.flows_expired, a.flows_expired);
  for (std::size_t i = 0; i < kAppCount; ++i) {
    const auto app = to_string(static_cast<AppId>(i));
    EXPECT_EQ(b.apps[i].flows, a.apps[i].flows) << app;
    EXPECT_EQ(b.apps[i].packets, a.apps[i].packets) << app;
    EXPECT_EQ(b.apps[i].bytes, a.apps[i].bytes) << app;
  }
  EXPECT_EQ(b.sni_flows, a.sni_flows);
}

using FlowKeyId = std::tuple<std::uint32_t, std::uint32_t, std::uint16_t, std::uint16_t, std::uint8_t>;

FlowKeyId flow_of(const Packet& p) {
  const auto tuple = peek_tuple(p.data());
  if (!tuple) {
    return {};  // non-IP: all in one group
  }
  const FiveTuple k = normalize(*tuple).key;
  return {k.ip_lo, k.ip_hi, k.port_lo, k.port_hi, k.protocol};
}

// Per flow, the sequence of output packets (identified by timestamp).
std::map<FlowKeyId, std::vector<std::uint64_t>> per_flow_order(const std::vector<Packet>& packets) {
  std::map<FlowKeyId, std::vector<std::uint64_t>> order;
  for (const Packet& p : packets) {
    order[flow_of(p)].push_back(p.ts_ns);
  }
  return order;
}

// Output packets ordered by timestamp. The generated captures give every
// record a unique timestamp, so this is a total order (asserted below).
// Sorting by timestamp alone also sidesteps a GCC 13 -Wstringop-overread
// false positive in std::vector<uint8_t>'s three-way comparison.
std::vector<std::pair<std::uint64_t, std::vector<std::uint8_t>>> sorted_contents(
    const std::vector<Packet>& packets) {
  std::vector<std::pair<std::uint64_t, std::vector<std::uint8_t>>> all;
  for (const Packet& p : packets) {
    all.emplace_back(p.ts_ns, p.bytes);
  }
  const auto by_time = [](const auto& a, const auto& b) { return a.first < b.first; };
  std::sort(all.begin(), all.end(), by_time);
  const auto same_time = [](const auto& a, const auto& b) { return a.first == b.first; };
  EXPECT_EQ(std::adjacent_find(all.begin(), all.end(), same_time), all.end())
      << "timestamps must be unique for this comparison";
  return all;
}

class Determinism : public ::testing::TestWithParam<std::tuple<std::string, EngineConfig>> {};

TEST_P(Determinism, PipelineMatchesSequentialBaseline) {
  const auto& [capture, config] = GetParam();
  const RunOutput baseline = run_file_sequential(capture);
  const RunOutput threaded = run_file_pipeline(capture, config);

  expect_same_results(baseline.stats, threaded.stats);

  const std::vector<Packet> want = read_all(baseline.pcap);
  const std::vector<Packet> got = read_all(threaded.pcap);
  // Same set of output packets...
  EXPECT_EQ(sorted_contents(got), sorted_contents(want));
  // ...and within every flow, the same order.
  EXPECT_EQ(per_flow_order(got), per_flow_order(want));
}

std::string layout_name(const ::testing::TestParamInfo<Determinism::ParamType>& info) {
  const auto& [capture, c] = info.param;
  std::string name = capture.substr(0, capture.find('.')) + "_" + std::to_string(c.num_lbs) + "x" +
                     std::to_string(c.fps_per_lb) + "_q" + std::to_string(c.queue_capacity);
  return name;
}

INSTANTIATE_TEST_SUITE_P(
    Layouts, Determinism,
    ::testing::Combine(::testing::Values("mixed.pcap", "malformed.pcap", "many_flows.pcap", "tls_split.pcap"),
                       ::testing::Values(layout(1, 1, 4096), layout(2, 2, 4096), layout(4, 4, 4096),
                                         layout(3, 5, 16), layout(4, 4, 1), layout(1, 8, 2))),
    layout_name);

TEST(Pipeline, SpreadsFlowsAcrossEveryWorker) {
  const RunStats s = run_file_pipeline("many_flows.pcap", layout(4, 4, 256)).stats;
  ASSERT_EQ(s.lbs.size(), 4u);
  ASSERT_EQ(s.fps.size(), 16u);
  std::uint64_t lb_total = 0;
  for (const LbStats& lb : s.lbs) {
    EXPECT_GT(lb.packets, 0u);
    lb_total += lb.packets;
  }
  EXPECT_EQ(lb_total, s.reader.packets);
  std::uint64_t fp_total = 0;
  for (const FpStats& fp : s.fps) {
    EXPECT_GT(fp.flows_created, 20u);  // 1000 flows over 16 workers: ~62 each
    fp_total += fp.packets;
  }
  EXPECT_EQ(fp_total, s.reader.packets);
}

// Repeated runs with a 1-slot queue: maximum contention for TSan to watch.
TEST(Pipeline, RepeatedRunsUnderContentionAgree) {
  const RunStats first = run_file_pipeline("many_flows.pcap", layout(4, 4, 1)).stats;
  for (int i = 0; i < 4; ++i) {
    expect_same_results(first, run_file_pipeline("many_flows.pcap", layout(4, 4, 1)).stats);
  }
}

}  // namespace
}  // namespace dpi
