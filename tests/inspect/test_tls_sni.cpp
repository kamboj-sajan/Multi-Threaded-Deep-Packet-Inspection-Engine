#include <gtest/gtest.h>

#include <random>
#include <string>

#include "dpi/inspect/tls_sni.hpp"
#include "fixtures/openssl_client_hello.hpp"
#include "tls_builder.hpp"

namespace dpi {
namespace {

using test::build_client_hello;
using test::Bytes;
using test::HelloLayout;
using test::HelloSpec;
using test::set16;

Bytes real_hello() { return Bytes(test::kOpensslClientHello.begin(), test::kOpensslClientHello.end()); }

SniResult parse(const Bytes& b) { return parse_tls_client_hello(b); }

// --- valid hellos --------------------------------------------------------

TEST(TlsSni, ExtractsSniFromRealOpensslClientHello) {
  const SniResult r = parse(real_hello());
  EXPECT_EQ(r.status, SniStatus::Found);
  EXPECT_EQ(r.sni, test::kOpensslHelloSni);
}

TEST(TlsSni, TrailingBytesAfterTheRecordAreIgnored) {
  Bytes b = real_hello();
  b.insert(b.end(), {0x17, 0x03, 0x03, 0x00, 0x05});  // next record starts
  EXPECT_EQ(parse(b).status, SniStatus::Found);
}

TEST(TlsSni, ExtractsSniFromBuiltHello) {
  const SniResult r = parse(build_client_hello({}).bytes);
  EXPECT_EQ(r.status, SniStatus::Found);
  EXPECT_EQ(r.sni, "www.example.com");
}

TEST(TlsSni, CanonicalisesTheName) {
  HelloSpec s;
  s.sni = "WWW.YouTube.COM.";
  const SniResult r = parse(build_client_hello(s).bytes);
  EXPECT_EQ(r.status, SniStatus::Found);
  EXPECT_EQ(r.sni, "www.youtube.com");
}

TEST(TlsSni, HelloWithoutServerNameExtension) {
  HelloSpec s;
  s.sni.reset();
  EXPECT_EQ(parse(build_client_hello(s).bytes).status, SniStatus::NoSni);
}

TEST(TlsSni, HelloWithoutAnyExtensions) {
  HelloSpec s;
  s.include_extensions = false;
  EXPECT_EQ(parse(build_client_hello(s).bytes).status, SniStatus::NoSni);
}

TEST(TlsSni, ManyExtensionsBeforeAndAfterSni) {
  HelloSpec s;
  s.extensions_before_sni = 300;
  s.extensions_after_sni = 300;
  s.sni = "deep.example.org";
  const SniResult r = parse(build_client_hello(s).bytes);
  EXPECT_EQ(r.status, SniStatus::Found);
  EXPECT_EQ(r.sni, "deep.example.org");
}

TEST(TlsSni, SkipsNonHostNameEntries) {
  HelloSpec s;
  s.non_host_name_entry_first = true;
  const SniResult r = parse(build_client_hello(s).bytes);
  EXPECT_EQ(r.status, SniStatus::Found);
  EXPECT_EQ(r.sni, "www.example.com");
}

TEST(TlsSni, AcceptsEmptySessionIdAndTls13RecordVersion) {
  HelloSpec s;
  s.session_id_len = 0;
  s.record_version = 0x0303;
  EXPECT_EQ(parse(build_client_hello(s).bytes).status, SniStatus::Found);
}

// --- not a ClientHello ---------------------------------------------------

TEST(TlsSni, RejectsOtherRecordsAndMessages) {
  HelloSpec app_data;
  app_data.content_type = 0x17;
  EXPECT_EQ(parse(build_client_hello(app_data).bytes).status, SniStatus::NotClientHello);

  HelloSpec server_hello;
  server_hello.handshake_type = 0x02;
  EXPECT_EQ(parse(build_client_hello(server_hello).bytes).status, SniStatus::NotClientHello);

  HelloSpec sslv2;
  sslv2.record_version = 0x0200;
  EXPECT_EQ(parse(build_client_hello(sslv2).bytes).status, SniStatus::NotClientHello);

  const std::string http = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
  EXPECT_EQ(parse(Bytes(http.begin(), http.end())).status, SniStatus::NotClientHello);
}

// --- truncation and malformed lengths -------------------------------------

TEST(TlsSni, EveryPrefixOfARealHelloIsIncomplete) {
  const Bytes full = real_hello();
  for (std::size_t len = 0; len < full.size(); ++len) {
    const Bytes prefix(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(len));  // exact-size copy for ASan
    EXPECT_EQ(parse(prefix).status, SniStatus::Incomplete) << "prefix " << len;
  }
}

struct LengthCase {
  const char* name;
  std::size_t HelloLayout::*field;
  int delta;  // added to the correct value
  SniStatus expected;
};

TEST(TlsSni, InconsistentLengthsAreMalformed) {
  const HelloLayout good = build_client_hello({});
  const std::vector<LengthCase> cases = {
      {"record +1", &HelloLayout::record_len, +1, SniStatus::Incomplete},  // needs one more byte
      {"handshake +1", &HelloLayout::handshake_len, +1, SniStatus::Malformed},
      {"cipher_suites +2", &HelloLayout::cipher_suites_len, +2, SniStatus::Malformed},
      {"cipher_suites +1 (odd)", &HelloLayout::cipher_suites_len, +1, SniStatus::Malformed},
      {"extensions +1", &HelloLayout::extensions_len, +1, SniStatus::Malformed},
      {"extensions -1", &HelloLayout::extensions_len, -1, SniStatus::Malformed},
      {"sni extension +1", &HelloLayout::sni_ext_len, +1, SniStatus::Malformed},
      {"sni list +1", &HelloLayout::sni_list_len, +1, SniStatus::Malformed},
      {"sni name +1", &HelloLayout::sni_name_len, +1, SniStatus::Malformed},
      {"sni name +200", &HelloLayout::sni_name_len, +200, SniStatus::Malformed},
  };
  for (const LengthCase& c : cases) {
    Bytes b = good.bytes;
    const std::size_t at = good.*(c.field);
    const auto current = static_cast<std::uint16_t>((b[at] << 8) | b[at + 1]);
    if (c.field == &HelloLayout::handshake_len) {
      set16(b, at + 1, static_cast<std::uint16_t>(current + c.delta));  // u24: low 16 bits
    } else {
      set16(b, at, static_cast<std::uint16_t>(current + c.delta));
    }
    EXPECT_EQ(to_string(parse(b).status), to_string(c.expected)) << c.name;
  }
}

TEST(TlsSni, OutOfRangeLengthFieldsAreMalformed) {
  HelloLayout h = build_client_hello({});
  Bytes b = h.bytes;
  set16(b, h.record_len, 0xFFFF);  // beyond any legal TLS record
  EXPECT_EQ(parse(b).status, SniStatus::Malformed);

  b = h.bytes;
  b[h.session_id_len] = 33;  // session ids are at most 32 bytes
  EXPECT_EQ(parse(b).status, SniStatus::Malformed);

  b = h.bytes;
  set16(b, h.cipher_suites_len, 0);
  EXPECT_EQ(parse(b).status, SniStatus::Malformed);

  b = h.bytes;
  b[h.compression_len] = 0;
  EXPECT_EQ(parse(b).status, SniStatus::Malformed);
}

TEST(TlsSni, DuplicateServerNameExtensionIsMalformed) {
  HelloLayout h = build_client_hello({});
  // Re-append a copy of the whole server_name extension and fix lengths.
  const std::size_t ext_start = h.sni_ext_len - 2;
  const std::size_t ext_size = 4 + ((h.bytes[h.sni_ext_len] << 8) | h.bytes[h.sni_ext_len + 1]);
  Bytes b = h.bytes;
  b.insert(b.end(), h.bytes.begin() + static_cast<std::ptrdiff_t>(ext_start),
           h.bytes.begin() + static_cast<std::ptrdiff_t>(ext_start + ext_size));
  auto bump16 = [&](std::size_t at) {
    set16(b, at, static_cast<std::uint16_t>(((b[at] << 8) | b[at + 1]) + ext_size));
  };
  bump16(h.extensions_len);
  bump16(h.handshake_len + 1);
  bump16(h.record_len);
  EXPECT_EQ(parse(b).status, SniStatus::Malformed);
}

TEST(TlsSni, RejectsInvalidHostNames) {
  for (const char* bad : {"", "exa mple.com", "a..b", ".lead.com", "ünïcode.com", "x\x01y.com"}) {
    HelloSpec s;
    s.sni = bad;
    EXPECT_EQ(parse(build_client_hello(s).bytes).status, SniStatus::Malformed) << bad;
  }
}

TEST(TlsSni, SurvivesRandomMutations) {
  std::mt19937 rng(99);
  const Bytes base = real_hello();
  for (int iter = 0; iter < 20000; ++iter) {
    Bytes b = base;
    const int flips = 1 + static_cast<int>(rng() % 4);
    for (int i = 0; i < flips; ++i) {
      // Bias towards the header area, where the length fields are.
      const std::size_t at = rng() % 2 ? rng() % 64 : rng() % b.size();
      b[at] = static_cast<std::uint8_t>(rng());
    }
    if (rng() % 4 == 0) {
      b.resize(rng() % (b.size() + 1));
    }
    const SniResult r = parse(b);
    if (r.status == SniStatus::Found) {
      EXPECT_FALSE(r.sni.empty());
    }
  }
}

}  // namespace
}  // namespace dpi
