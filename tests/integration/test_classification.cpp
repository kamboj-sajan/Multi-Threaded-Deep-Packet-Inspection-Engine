// Classification results on the generated captures. Expected values are
// the per-app and per-SNI tables in tests/data/MANIFEST.md.

#include <gtest/gtest.h>

#include <map>
#include <unordered_map>
#include <string>

#include "dpi/pipeline/report.hpp"
#include "run_helpers.hpp"

namespace dpi {
namespace {

using test::run_file_sequential;
using AppFlows = std::map<std::string, std::uint64_t>;

AppFlows flows_by_app(const FpStats& fp) {
  AppFlows out;
  for (std::size_t i = 0; i < kAppCount; ++i) {
    if (fp.apps[i].flows > 0) {
      out[std::string(to_string(static_cast<AppId>(i)))] = fp.apps[i].flows;
    }
  }
  return out;
}

TEST(Classification, MixedCapture) {
  const FpStats fp = run_file_sequential("mixed.pcap").stats.merged_fast_path();
  EXPECT_EQ(flows_by_app(fp), (AppFlows{{"DNS", 3},       {"Facebook", 2}, {"GitHub", 2},  {"Google", 1},
                                        {"HTTP", 1},      {"HTTPS", 3},    {"Instagram", 1}, {"Netflix", 2},
                                        {"TikTok", 1},    {"Unknown", 10}, {"WhatsApp", 1}, {"YouTube", 3}}));

  // 14 distinct names: 12 TLS SNIs (one hello has none) plus 2 HTTP Hosts.
  EXPECT_EQ(fp.sni_flows.size(), 14u);
  EXPECT_EQ(fp.sni_flows.at("www.youtube.com"), 2u);
  EXPECT_EQ(fp.sni_flows.at("www.netflix.com"), 2u);  // once over TLS, once over HTTP
  EXPECT_EQ(fp.sni_flows.at("many-extensions.example.net"), 1u);
  EXPECT_EQ(fp.sni_flows.at("api.github.com"), 1u);  // the VLAN-tagged flow

  const auto top = top_snis(fp, kTopSniCount);
  ASSERT_EQ(top.size(), 10u);
  EXPECT_EQ(top[0].sni, "www.netflix.com");
  EXPECT_EQ(top[1].sni, "www.youtube.com");
  EXPECT_EQ(top[2].sni, "api.github.com");  // ties sorted by name
}

TEST(Classification, ManyFlowsCapture) {
  const FpStats fp = run_file_sequential("many_flows.pcap").stats.merged_fast_path();
  EXPECT_EQ(flows_by_app(fp), (AppFlows{{"DNS", 200},      {"Facebook", 82}, {"GitHub", 69},  {"Google", 72},
                                        {"HTTP", 100},     {"HTTPS", 81},    {"Instagram", 82}, {"Netflix", 73},
                                        {"Unknown", 100},  {"YouTube", 141}}));
  EXPECT_EQ(fp.sni_flows, (std::unordered_map<std::string, std::uint64_t>{
                              {"example.com", 100},      {"github.com", 69},        {"i.ytimg.com", 71},
                              {"unknown-site.example", 81}, {"www.facebook.com", 82}, {"www.google.com", 72},
                              {"www.instagram.com", 82}, {"www.netflix.com", 73},   {"www.youtube.com", 70}}));
}

TEST(Classification, SplitClientHellosAreReassembled) {
  const FpStats fp = run_file_sequential("tls_split.pcap").stats.merged_fast_path();
  // 2- and 3-segment hellos and a 2-segment HTTP request are recognised;
  // the out-of-order hello falls back to the port (443 -> HTTPS).
  EXPECT_EQ(flows_by_app(fp), (AppFlows{{"GitHub", 1}, {"HTTPS", 1}, {"Netflix", 1}, {"YouTube", 1}}));
  EXPECT_EQ(fp.sni_flows, (std::unordered_map<std::string, std::uint64_t>{
                              {"github.com", 1}, {"www.netflix.com", 1}, {"www.youtube.com", 1}}));
}

}  // namespace
}  // namespace dpi
