// How rule verdicts apply packet by packet in the fast path.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "connection.hpp"
#include "dpi/pipeline/stages.hpp"
#include "tls_builder.hpp"

namespace dpi {
namespace {

using test::Bytes;
using test::Connection;

constexpr Verdict F = Verdict::Forward;
constexpr Verdict D = Verdict::Drop;

FastPathStage stage_with(const std::string& rules) {
  FastPathConfig config;
  config.rules = std::make_shared<const RuleSet>(RuleSet::parse(rules));
  return FastPathStage(config);
}

Bytes hello(const std::string& sni) {
  test::HelloSpec s;
  s.sni = sni;
  return test::build_client_hello(s).bytes;
}

TEST(FastPathRules, IpRuleDropsTheWholeFlowFromItsFirstPacket) {
  FastPathStage fp = stage_with("block ip 10.0.0.2");
  Connection c(fp);
  EXPECT_EQ(c.handshake(), (std::vector<Verdict>{D, D, D}));
  EXPECT_EQ(c.client(hello("www.example.com")), D);
  fp.finish();
  EXPECT_EQ(fp.stats().dropped, 4u);
  EXPECT_EQ(fp.stats().flows_blocked_by_reason[static_cast<std::size_t>(BlockReason::Ip)], 1u);
}

TEST(FastPathRules, PortRuleDropsFromTheFirstPacket) {
  FastPathStage fp = stage_with("block port 6881");
  Connection c(fp, 6881);
  EXPECT_EQ(c.handshake(), (std::vector<Verdict>{D, D, D}));
}

TEST(FastPathRules, DomainRuleForwardsTheHandshakeThenDrops) {
  FastPathStage fp = stage_with("block domain *.tiktok.com");
  Connection c(fp);
  // The SNI is unknown during the TCP handshake, so it is forwarded...
  EXPECT_EQ(c.handshake(), (std::vector<Verdict>{F, F, F}));
  // ...and the flow is blocked from the ClientHello on.
  EXPECT_EQ(c.client(hello("www.tiktok.com")), D);
  EXPECT_EQ(c.server(Bytes(200, 0x16)), D);
  EXPECT_EQ(c.client(Bytes(64, 0x17)), D);
  fp.finish();
  EXPECT_EQ(fp.stats().forwarded, 3u);
  EXPECT_EQ(fp.stats().dropped, 3u);
  EXPECT_EQ(fp.stats().flows_blocked_by_reason[static_cast<std::size_t>(BlockReason::Domain)], 1u);
}

TEST(FastPathRules, AppRuleMatchesTheClassifiedApp) {
  FastPathStage fp = stage_with("block app YouTube");
  Connection youtube(fp, 443, 40001);
  youtube.handshake();
  EXPECT_EQ(youtube.client(hello("rr1---sn-x.googlevideo.com")), D);

  Connection other(fp, 443, 40002);
  other.handshake();
  EXPECT_EQ(other.client(hello("www.github.com")), F);
  EXPECT_EQ(other.server(Bytes(100, 1)), F);
}

TEST(FastPathRules, AppRuleCanMatchThePortBasedGuessImmediately) {
  FastPathStage fp = stage_with("block app HTTPS");
  Connection c(fp, 443);
  EXPECT_EQ(c.handshake(), (std::vector<Verdict>{D, D, D}));  // 443 -> HTTPS at creation
}

TEST(FastPathRules, VerdictIsStickyForTheRestOfTheFlow) {
  FastPathStage fp = stage_with("block domain blocked.example");
  Connection c(fp);
  c.handshake();
  EXPECT_EQ(c.client(hello("blocked.example")), D);
  // Nothing later can revive the flow, even payload that looks harmless.
  for (int i = 0; i < 10; ++i) {
    EXPECT_EQ(c.server(Bytes(100, static_cast<std::uint8_t>(i))), D);
    EXPECT_EQ(c.client(Bytes(50, 0x17)), D);
  }
}

TEST(FastPathRules, NewConnectionOnReusedTupleIsJudgedAfresh) {
  FastPathStage fp = stage_with("block domain blocked.example");
  Connection first(fp);
  first.handshake();
  EXPECT_EQ(first.client(hello("blocked.example")), D);
  first.send(false, tcpflag::kRst, {});

  Connection second(fp);  // same 5-tuple, new SYN
  EXPECT_EQ(second.handshake(), (std::vector<Verdict>{F, F, F}));
  EXPECT_EQ(second.client(hello("allowed.example")), F);
}

TEST(FastPathRules, NoRulesForwardsEverything) {
  FastPathStage fp;  // config.rules == nullptr
  Connection c(fp);
  EXPECT_EQ(c.handshake(), (std::vector<Verdict>{F, F, F}));
  EXPECT_EQ(c.client(hello("www.tiktok.com")), F);
}

}  // namespace
}  // namespace dpi
