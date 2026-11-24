#include <gtest/gtest.h>

#include <array>
#include <set>
#include <string>

#include "dpi/classifier/classifier.hpp"

namespace dpi {
namespace {

const Classifier& c = Classifier::builtin();

TEST(Classifier, MatchesExactDomainsAndSubdomains) {
  EXPECT_EQ(c.app_for_host("youtube.com"), AppId::YouTube);
  EXPECT_EQ(c.app_for_host("www.youtube.com"), AppId::YouTube);
  EXPECT_EQ(c.app_for_host("r4---sn-ab5l6nzr.googlevideo.com"), AppId::YouTube);
  EXPECT_EQ(c.app_for_host("www.netflix.com"), AppId::Netflix);
  EXPECT_EQ(c.app_for_host("www.facebook.com"), AppId::Facebook);
  EXPECT_EQ(c.app_for_host("scontent.xx.fbcdn.net"), AppId::Facebook);
  EXPECT_EQ(c.app_for_host("www.instagram.com"), AppId::Instagram);
  EXPECT_EQ(c.app_for_host("web.whatsapp.com"), AppId::WhatsApp);
  EXPECT_EQ(c.app_for_host("www.google.com"), AppId::Google);
  EXPECT_EQ(c.app_for_host("github.com"), AppId::GitHub);
  EXPECT_EQ(c.app_for_host("raw.githubusercontent.com"), AppId::GitHub);
  EXPECT_EQ(c.app_for_host("www.tiktok.com"), AppId::TikTok);
}

TEST(Classifier, MatchesOnlyOnLabelBoundaries) {
  // "netflix.com" ends with "x.com" but is not a subdomain of it.
  EXPECT_EQ(c.app_for_host("netflix.com"), AppId::Netflix);
  EXPECT_EQ(c.app_for_host("x.com"), AppId::Twitter);
  EXPECT_EQ(c.app_for_host("notyoutube.com"), AppId::Unknown);
  EXPECT_EQ(c.app_for_host("youtube.com.evil.example"), AppId::Unknown);
}

TEST(Classifier, LongestSuffixWins) {
  EXPECT_EQ(c.app_for_host("www.google.com"), AppId::Google);
  EXPECT_EQ(c.app_for_host("youtubei.googleapis.com"), AppId::YouTube);  // not Google
  EXPECT_EQ(c.app_for_host("storage.googleapis.com"), AppId::Google);
}

TEST(Classifier, UnknownHosts) {
  EXPECT_EQ(c.app_for_host("example.org"), AppId::Unknown);
  EXPECT_EQ(c.app_for_host("com"), AppId::Unknown);
  EXPECT_EQ(c.app_for_host(""), AppId::Unknown);
}

TEST(Classifier, CustomTableIsDataDriven) {
  constexpr std::array<DomainRule, 2> table = {{{"corp.example", AppId::Microsoft},
                                                {"video.corp.example", AppId::Zoom}}};
  const Classifier custom(table);
  EXPECT_EQ(custom.app_for_host("mail.corp.example"), AppId::Microsoft);
  EXPECT_EQ(custom.app_for_host("a.video.corp.example"), AppId::Zoom);
  EXPECT_EQ(custom.app_for_host("www.youtube.com"), AppId::Unknown);
}

TEST(Classifier, BuiltinTableHasNoDuplicateSuffixes) {
  std::set<std::string> seen;
  for (const DomainRule& rule : Classifier::builtin_table()) {
    EXPECT_TRUE(seen.insert(std::string(rule.suffix)).second) << "duplicate " << rule.suffix;
    EXPECT_NE(rule.app, AppId::Unknown);
  }
}

TEST(Classifier, PortFallback) {
  EXPECT_EQ(Classifier::app_for_port(6, 443), AppId::HTTPS);
  EXPECT_EQ(Classifier::app_for_port(6, 80), AppId::HTTP);
  EXPECT_EQ(Classifier::app_for_port(6, 8080), AppId::HTTP);
  EXPECT_EQ(Classifier::app_for_port(6, 22), AppId::SSH);
  EXPECT_EQ(Classifier::app_for_port(17, 53), AppId::DNS);
  EXPECT_EQ(Classifier::app_for_port(6, 53), AppId::DNS);
  EXPECT_EQ(Classifier::app_for_port(17, 443), AppId::QUIC);
  EXPECT_EQ(Classifier::app_for_port(17, 123), AppId::NTP);
  EXPECT_EQ(Classifier::app_for_port(6, 6881), AppId::Unknown);
  EXPECT_EQ(Classifier::app_for_port(1, 0), AppId::Unknown);  // ICMP
}

}  // namespace
}  // namespace dpi
