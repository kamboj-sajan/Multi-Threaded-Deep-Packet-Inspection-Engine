#include <gtest/gtest.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <thread>
#include <unistd.h>
#include <vector>

#include "dpi/rules/rule_set.hpp"

namespace dpi {
namespace {

constexpr std::uint32_t ip(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
  return (std::uint32_t{a} << 24) | (std::uint32_t{b} << 16) | (std::uint32_t{c} << 8) | d;
}

FlowFacts facts(std::uint32_t a, std::uint32_t b, std::uint16_t pa = 40000, std::uint16_t pb = 443,
                AppId app = AppId::HTTPS, std::string_view host = {}) {
  return FlowFacts{a, b, pa, pb, app, host};
}

std::string error_of(std::string_view text) {
  try {
    RuleSet::parse(text, "rules.txt");
  } catch (const RuleError& e) {
    return e.what();
  }
  return "";
}

TEST(Rules, ParsesTheExampleFormat) {
  const RuleSet r = RuleSet::parse(
      "# comment line\n"
      "\n"
      "block ip 192.168.1.50\n"
      "BLOCK DOMAIN *.TikTok.com   # trailing comment\n"
      "block app youtube\r\n"
      "  block   port   6881  \n");
  EXPECT_EQ(r.size(), 4u);
  EXPECT_TRUE(r.blocks_ip(ip(192, 168, 1, 50)));
  EXPECT_TRUE(r.blocks_host("www.tiktok.com"));
  EXPECT_TRUE(r.blocks_app(AppId::YouTube));
  EXPECT_TRUE(r.blocks_port(6881));
}

TEST(Rules, EmptyRuleSetAllowsEverything) {
  const RuleSet r = RuleSet::parse("# nothing here\n\n");
  EXPECT_TRUE(r.empty());
  EXPECT_EQ(r.evaluate(facts(ip(1, 2, 3, 4), ip(5, 6, 7, 8))), BlockReason::None);
}

TEST(Rules, IpRulesMatchEitherEndpointAndCidrBlocks) {
  const RuleSet r = RuleSet::parse("block ip 192.168.1.50\nblock ip 10.0.0.0/8\n");
  EXPECT_EQ(r.evaluate(facts(ip(192, 168, 1, 50), ip(8, 8, 8, 8))), BlockReason::Ip);
  EXPECT_EQ(r.evaluate(facts(ip(8, 8, 8, 8), ip(192, 168, 1, 50))), BlockReason::Ip);
  EXPECT_EQ(r.evaluate(facts(ip(10, 200, 3, 4), ip(8, 8, 8, 8))), BlockReason::Ip);
  EXPECT_EQ(r.evaluate(facts(ip(11, 0, 0, 1), ip(192, 168, 1, 51))), BlockReason::None);
}

TEST(Rules, CidrEdgeCases) {
  const RuleSet all = RuleSet::parse("block ip 0.0.0.0/0");
  EXPECT_TRUE(all.blocks_ip(ip(1, 2, 3, 4)));
  const RuleSet host = RuleSet::parse("block ip 172.16.5.9/32");
  EXPECT_TRUE(host.blocks_ip(ip(172, 16, 5, 9)));
  EXPECT_FALSE(host.blocks_ip(ip(172, 16, 5, 8)));
  const RuleSet unaligned = RuleSet::parse("block ip 172.16.5.9/16");  // host bits ignored
  EXPECT_TRUE(unaligned.blocks_ip(ip(172, 16, 200, 1)));
}

TEST(Rules, PortRulesMatchEitherPort) {
  const RuleSet r = RuleSet::parse("block port 6881");
  EXPECT_EQ(r.evaluate(facts(1, 2, 51413, 6881)), BlockReason::Port);
  EXPECT_EQ(r.evaluate(facts(1, 2, 6881, 443)), BlockReason::Port);
  EXPECT_EQ(r.evaluate(facts(1, 2, 6882, 443)), BlockReason::None);
}

TEST(Rules, AppRulesAreCaseInsensitive) {
  const RuleSet r = RuleSet::parse("block app YOUTUBE\nblock app https");
  EXPECT_EQ(r.evaluate(facts(1, 2, 1, 2, AppId::YouTube)), BlockReason::App);
  EXPECT_EQ(r.evaluate(facts(1, 2, 1, 2, AppId::HTTPS)), BlockReason::App);
  EXPECT_EQ(r.evaluate(facts(1, 2, 1, 2, AppId::Netflix)), BlockReason::None);
}

TEST(Rules, WildcardDomainCoversTheNameAndItsSubdomains) {
  const RuleSet r = RuleSet::parse("block domain *.tiktok.com");
  EXPECT_TRUE(r.blocks_host("tiktok.com"));
  EXPECT_TRUE(r.blocks_host("www.tiktok.com"));
  EXPECT_TRUE(r.blocks_host("a.b.c.tiktok.com"));
  EXPECT_FALSE(r.blocks_host("nottiktok.com"));       // label boundary
  EXPECT_FALSE(r.blocks_host("tiktok.com.evil.net"));
  EXPECT_FALSE(r.blocks_host(""));
}

TEST(Rules, ExactDomainCoversOnlyThatName) {
  const RuleSet r = RuleSet::parse("block domain Example.ORG.");
  EXPECT_TRUE(r.blocks_host("example.org"));
  EXPECT_FALSE(r.blocks_host("www.example.org"));
}

TEST(Rules, EvaluationOrderIsIpPortAppDomain) {
  const RuleSet r = RuleSet::parse(
      "block domain *.youtube.com\nblock app YouTube\nblock port 443\nblock ip 9.9.9.9");
  EXPECT_EQ(r.evaluate(facts(ip(9, 9, 9, 9), 1, 1, 443, AppId::YouTube, "www.youtube.com")), BlockReason::Ip);
  EXPECT_EQ(r.evaluate(facts(1, 2, 1, 443, AppId::YouTube, "www.youtube.com")), BlockReason::Port);
  EXPECT_EQ(r.evaluate(facts(1, 2, 1, 80, AppId::YouTube, "www.youtube.com")), BlockReason::App);
  EXPECT_EQ(r.evaluate(facts(1, 2, 1, 80, AppId::HTTP, "m.youtube.com")), BlockReason::Domain);
}

TEST(Rules, ErrorsNameTheFileAndLine) {
  EXPECT_EQ(error_of("block ip 1.2.3.4\nallow ip 1.2.3.4\n"),
            "rules.txt:2: unknown action 'allow' (expected 'block')");
  EXPECT_NE(error_of("\n\nblock ip 300.1.1.1").find("rules.txt:3: invalid IPv4 address"), std::string::npos);
  EXPECT_NE(error_of("block ip 1.2.3.4/33").find("invalid CIDR prefix"), std::string::npos);
  EXPECT_NE(error_of("block port 0").find("invalid port '0'"), std::string::npos);
  EXPECT_NE(error_of("block port 70000").find("invalid port"), std::string::npos);
  EXPECT_NE(error_of("block port 80x").find("invalid port"), std::string::npos);
  EXPECT_NE(error_of("block app Youtub").find("unknown app 'Youtub'; known apps: HTTP"), std::string::npos);
  EXPECT_NE(error_of("block app Unknown").find("unknown app"), std::string::npos);
  EXPECT_NE(error_of("block domain bad..name").find("invalid domain"), std::string::npos);
  EXPECT_NE(error_of("block url http://x").find("unknown rule type 'url'"), std::string::npos);
  EXPECT_NE(error_of("block ip").find("expected 'block <ip|port|app|domain> <value>'"), std::string::npos);
  EXPECT_NE(error_of("block ip 1.2.3.4 extra").find("expected 'block"), std::string::npos);
}

TEST(Rules, LoadsFromFile) {
  const auto path = std::filesystem::temp_directory_path() / ("dpi_rules_" + std::to_string(::getpid()) + ".txt");
  {
    std::ofstream out(path);
    out << "block port 6881\nblock app Netflix\n";
  }
  const std::shared_ptr<const RuleSet> r = RuleSet::load_file(path.string());
  EXPECT_EQ(r->size(), 2u);
  std::filesystem::remove(path);
  EXPECT_THROW(RuleSet::load_file("/nonexistent/rules.txt"), RuleError);
}

// The fast-path threads share one RuleSet read-only; under ThreadSanitizer
// this proves concurrent evaluation needs no locking.
TEST(Rules, ConcurrentReadersShareOneInstance) {
  const auto rules = std::make_shared<const RuleSet>(
      RuleSet::parse("block ip 10.0.0.0/8\nblock domain *.tiktok.com\nblock app YouTube\nblock port 6881"));
  std::atomic<std::uint64_t> blocked{0};
  std::vector<std::thread> threads;
  for (int t = 0; t < 8; ++t) {
    threads.emplace_back([rules, &blocked, t] {
      std::uint64_t local = 0;
      for (std::uint32_t i = 0; i < 20000; ++i) {
        const FlowFacts f = facts(ip(static_cast<std::uint8_t>(9 + i % 3), 0, 0, 1), ip(8, 8, 8, 8),
                                  static_cast<std::uint16_t>(6880 + (i + t) % 3), 443,
                                  i % 5 == 0 ? AppId::YouTube : AppId::HTTPS,
                                  i % 7 == 0 ? "www.tiktok.com" : "example.com");
        local += rules->evaluate(f) != BlockReason::None;
      }
      blocked += local;
    });
  }
  for (auto& th : threads) {
    th.join();
  }
  EXPECT_GT(blocked.load(), 0u);
}

}  // namespace
}  // namespace dpi
