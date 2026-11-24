#include <gtest/gtest.h>

#include <random>
#include <string>

#include "dpi/inspect/hostname.hpp"
#include "dpi/inspect/http_host.hpp"

namespace dpi {
namespace {

HttpHostResult parse(const std::string& s) {
  const auto* p = reinterpret_cast<const std::uint8_t*>(s.data());
  return parse_http_host(ByteView(p, s.size()));
}

TEST(HttpHost, ExtractsHostFromGetRequest) {
  const auto r = parse("GET /watch?v=1 HTTP/1.1\r\nHost: www.youtube.com\r\nAccept: */*\r\n\r\n");
  EXPECT_EQ(r.status, HttpHostStatus::Found);
  EXPECT_EQ(r.host, "www.youtube.com");
}

TEST(HttpHost, HeaderNameIsCaseInsensitiveAndValueIsCanonical) {
  const auto r = parse("POST /api HTTP/1.0\r\nUser-Agent: x\r\nhOsT:   API.GitHub.com:8080  \r\n\r\n");
  EXPECT_EQ(r.status, HttpHostStatus::Found);
  EXPECT_EQ(r.host, "api.github.com");
}

TEST(HttpHost, AcceptsBareLineFeeds) {
  const auto r = parse("HEAD / HTTP/1.1\nHost: example.com\n\n");
  EXPECT_EQ(r.status, HttpHostStatus::Found);
  EXPECT_EQ(r.host, "example.com");
}

TEST(HttpHost, HostFoundBeforeHeadersEnd) {
  const auto r = parse("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: abc");
  EXPECT_EQ(r.status, HttpHostStatus::Found);
}

TEST(HttpHost, CompleteRequestWithoutHost) {
  EXPECT_EQ(parse("GET / HTTP/1.0\r\nAccept: */*\r\n\r\n").status, HttpHostStatus::NoHost);
}

TEST(HttpHost, UnusableHostValues) {
  EXPECT_EQ(parse("GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n").status, HttpHostStatus::NoHost);
  EXPECT_EQ(parse("GET / HTTP/1.1\r\nHost: example.com:http\r\n\r\n").status, HttpHostStatus::NoHost);
  EXPECT_EQ(parse("GET / HTTP/1.1\r\nHost: \r\n\r\n").status, HttpHostStatus::NoHost);
}

TEST(HttpHost, RecognisesNonHttpPayloads) {
  EXPECT_EQ(parse("\x16\x03\x01\x02\x00").status, HttpHostStatus::NotHttp);
  EXPECT_EQ(parse("SSH-2.0-OpenSSH_9.6\r\n").status, HttpHostStatus::NotHttp);
  EXPECT_EQ(parse("GET /index.html\r\n").status, HttpHostStatus::NotHttp);  // HTTP/0.9
  EXPECT_EQ(parse("get / HTTP/1.1\r\n").status, HttpHostStatus::NotHttp);   // methods are case-sensitive
}

TEST(HttpHost, PartialRequestsAreIncomplete) {
  EXPECT_EQ(parse("GE").status, HttpHostStatus::Incomplete);
  EXPECT_EQ(parse("GET / HTTP/1.1").status, HttpHostStatus::Incomplete);
  EXPECT_EQ(parse("GET / HTTP/1.1\r\nUser-Agent: curl\r\n").status, HttpHostStatus::Incomplete);
  EXPECT_EQ(parse("GET / HTTP/1.1\r\nHost: exam").status, HttpHostStatus::Incomplete);
}

TEST(HttpHost, GivesUpAfterTheHeaderLimit) {
  const std::string huge = "GET / HTTP/1.1\r\nX-Pad: " + std::string(10000, 'a');
  EXPECT_EQ(parse(huge).status, HttpHostStatus::NoHost);
}

TEST(HttpHost, SurvivesRandomBytes) {
  std::mt19937 rng(5);
  for (int i = 0; i < 5000; ++i) {
    std::string s = rng() % 2 ? "GET / HTTP/1.1\r\nHost: " : "";
    const std::size_t n = rng() % 64;
    for (std::size_t j = 0; j < n; ++j) {
      s.push_back(static_cast<char>(rng()));
    }
    (void)parse(s);
  }
}

TEST(Hostname, Canonicalisation) {
  EXPECT_EQ(canonical_hostname("Example.COM."), "example.com");
  EXPECT_EQ(canonical_hostname("_dmarc.example.com"), "_dmarc.example.com");
  EXPECT_EQ(canonical_hostname("localhost"), "localhost");
  EXPECT_FALSE(canonical_hostname("").has_value());
  EXPECT_FALSE(canonical_hostname(".").has_value());
  EXPECT_FALSE(canonical_hostname(".example.com").has_value());
  EXPECT_FALSE(canonical_hostname("a..b").has_value());
  EXPECT_FALSE(canonical_hostname("a b").has_value());
  EXPECT_FALSE(canonical_hostname(std::string(254, 'a')).has_value());
  EXPECT_TRUE(canonical_hostname(std::string(253, 'a')).has_value());
}

}  // namespace
}  // namespace dpi
