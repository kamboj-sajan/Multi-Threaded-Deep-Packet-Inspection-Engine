// Fast-path inspection: which packets are inspected, reassembly of split
// ClientHellos, and that classified flows stop being inspected.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "dpi/pipeline/stages.hpp"
#include "pcap_builder.hpp"
#include "tls_builder.hpp"

namespace dpi {
namespace {

using test::Bytes;
using test::FrameSpec;

constexpr std::uint8_t kSyn = tcpflag::kSyn;
constexpr std::uint8_t kSynAck = tcpflag::kSyn | tcpflag::kAck;
constexpr std::uint8_t kAck = tcpflag::kAck;
constexpr std::uint8_t kPshAck = tcpflag::kPsh | tcpflag::kAck;

Bytes hello_for(const std::string& sni) {
  test::HelloSpec s;
  s.sni = sni;
  s.extensions_before_sni = 40;  // make it big enough to split meaningfully
  return test::build_client_hello(s).bytes;
}

Bytes text(const std::string& s) { return Bytes(s.begin(), s.end()); }

// Drives one TCP connection through a FastPathStage.
class Connection {
 public:
  explicit Connection(FastPathStage& fp, std::uint16_t server_port = 443, std::uint16_t client_port = 40000)
      : fp_(fp), server_port_(server_port), client_port_(client_port) {}

  void handshake() {
    send(true, kSyn, {});
    send(false, kSynAck, {});
    send(true, kAck, {});
  }

  // Sends `payload` from the client with the next sequence number.
  void client(const Bytes& payload, std::uint32_t seq_override = 0) {
    send(true, kPshAck, payload, seq_override);
  }
  void server(const Bytes& payload) { send(false, kPshAck, payload); }

 private:
  void send(bool from_client, std::uint8_t flags, const Bytes& payload, std::uint32_t seq_override = 0) {
    FrameSpec s = test::tcp_spec(payload);
    s.tcp_flags = flags;
    s.src_ip = from_client ? test::ip(10, 0, 0, 1) : test::ip(10, 0, 0, 2);
    s.dst_ip = from_client ? test::ip(10, 0, 0, 2) : test::ip(10, 0, 0, 1);
    s.src_port = from_client ? client_port_ : server_port_;
    s.dst_port = from_client ? server_port_ : client_port_;
    std::uint32_t& seq = from_client ? client_seq_ : server_seq_;
    s.tcp_seq = seq_override != 0 ? seq_override : seq;
    if (seq_override == 0) {
      seq += static_cast<std::uint32_t>(payload.size()) + ((flags & kSyn) ? 1 : 0);
    }
    Packet p;
    p.bytes = test::build_frame(s);
    p.orig_len = p.caplen();
    ParsedPacket parsed;
    ASSERT_EQ(parse_packet(p.data(), parsed), ParseStatus::Ok);
    fp_.process(p, parsed);
  }

  FastPathStage& fp_;
  std::uint16_t server_port_;
  std::uint16_t client_port_;
  std::uint32_t client_seq_ = 1000;
  std::uint32_t server_seq_ = 5000;
};

struct Outcome {
  AppId app;
  std::string sni;
};

// Runs `script` against a fresh stage and returns how the single flow ended.
template <typename Script>
Outcome classify(Script script, InspectionConfig config = {}) {
  FastPathConfig fp_config;
  fp_config.inspection = config;
  FastPathStage fp(fp_config);
  script(fp);
  fp.finish();
  Outcome out{AppId::Unknown, {}};
  std::size_t flows = 0;
  for (std::size_t i = 0; i < kAppCount; ++i) {
    if (fp.stats().apps[i].flows > 0) {
      out.app = static_cast<AppId>(i);
      flows += fp.stats().apps[i].flows;
    }
  }
  EXPECT_EQ(flows, 1u);
  if (!fp.stats().sni_flows.empty()) {
    out.sni = fp.stats().sni_flows.begin()->first;
  }
  return out;
}

TEST(Inspection, ClassifiesTlsBySni) {
  const Outcome o = classify([](FastPathStage& fp) {
    Connection c(fp);
    c.handshake();
    c.client(hello_for("www.youtube.com"));
    c.server(Bytes(100, 0x16));
  });
  EXPECT_EQ(o.app, AppId::YouTube);
  EXPECT_EQ(o.sni, "www.youtube.com");
}

TEST(Inspection, UnknownSniIsHttps) {
  const Outcome o = classify([](FastPathStage& fp) {
    Connection c(fp, 8443);
    c.handshake();
    c.client(hello_for("intranet.example"));
  });
  EXPECT_EQ(o.app, AppId::HTTPS);  // TLS seen, even on a non-443 port
  EXPECT_EQ(o.sni, "intranet.example");
}

TEST(Inspection, ClassifiesHttpByHostOnAnyPort) {
  const Outcome o = classify([](FastPathStage& fp) {
    Connection c(fp, 8080);
    c.handshake();
    c.client(text("GET / HTTP/1.1\r\nHost: www.netflix.com\r\n\r\n"));
  });
  EXPECT_EQ(o.app, AppId::Netflix);
  EXPECT_EQ(o.sni, "www.netflix.com");
}

TEST(Inspection, ReassemblesClientHelloSplitAcrossSegments) {
  const Bytes hello = hello_for("github.com");
  ASSERT_GT(hello.size(), 300u);
  const Outcome o = classify([&](FastPathStage& fp) {
    Connection c(fp);
    c.handshake();
    c.client(Bytes(hello.begin(), hello.begin() + 100));
    c.client(Bytes(hello.begin() + 100, hello.begin() + 250));
    c.client(Bytes(hello.begin() + 250, hello.end()));
  });
  EXPECT_EQ(o.app, AppId::GitHub);
  EXPECT_EQ(o.sni, "github.com");
}

TEST(Inspection, GivesUpOnOutOfOrderSegments) {
  const Bytes hello = hello_for("github.com");
  const Outcome o = classify([&](FastPathStage& fp) {
    Connection c(fp);
    c.handshake();
    c.client(Bytes(hello.begin(), hello.begin() + 100));
    c.client(Bytes(hello.begin() + 150, hello.end()), /*seq_override=*/999999);  // a gap
  });
  EXPECT_EQ(o.app, AppId::HTTPS);  // port fallback, no SNI
  EXPECT_TRUE(o.sni.empty());
}

TEST(Inspection, ReassemblyIsCapped) {
  InspectionConfig config;
  config.max_reassembly_bytes = 120;
  const Bytes hello = hello_for("github.com");
  const Outcome o = classify(
      [&](FastPathStage& fp) {
        Connection c(fp);
        c.handshake();
        c.client(Bytes(hello.begin(), hello.begin() + 100));
        c.client(Bytes(hello.begin() + 100, hello.end()));
      },
      config);
  EXPECT_EQ(o.app, AppId::HTTPS);
  EXPECT_TRUE(o.sni.empty());
}

TEST(Inspection, StopsInspectingOnceClassified) {
  const Outcome o = classify([](FastPathStage& fp) {
    Connection c(fp);
    c.handshake();
    c.client(hello_for("www.youtube.com"));
    // A later, different-looking payload must not change the result.
    c.client(text("GET / HTTP/1.1\r\nHost: www.tiktok.com\r\n\r\n"));
  });
  EXPECT_EQ(o.app, AppId::YouTube);
  EXPECT_EQ(o.sni, "www.youtube.com");
}

TEST(Inspection, OnlyTheFirstFewPayloadPacketsAreInspected) {
  InspectionConfig config;
  config.max_payload_packets = 2;
  const Outcome o = classify(
      [](FastPathStage& fp) {
        Connection c(fp);
        c.handshake();
        c.server(Bytes(10, 1));
        c.server(Bytes(10, 2));
        c.client(hello_for("www.youtube.com"));  // third payload packet: too late
      },
      config);
  EXPECT_EQ(o.app, AppId::HTTPS);
  EXPECT_TRUE(o.sni.empty());
}

TEST(Inspection, UnrecognisedPayloadKeepsPortGuess) {
  const Outcome o = classify([](FastPathStage& fp) {
    Connection c(fp, 22);
    c.handshake();
    c.client(text("SSH-2.0-OpenSSH_9.6\r\n"));
  });
  EXPECT_EQ(o.app, AppId::SSH);
}

TEST(Inspection, TlsWithoutSniIsHttps) {
  const Outcome o = classify([](FastPathStage& fp) {
    test::HelloSpec s;
    s.sni.reset();
    Connection c(fp, 9999);
    c.handshake();
    c.client(test::build_client_hello(s).bytes);
  });
  EXPECT_EQ(o.app, AppId::HTTPS);
  EXPECT_TRUE(o.sni.empty());
}

TEST(Inspection, UdpFlowsUsePortsOnly) {
  FastPathStage fp;
  FrameSpec s = test::udp_spec(Bytes(30, 0));
  s.dst_port = 53;
  Packet p;
  p.bytes = test::build_frame(s);
  p.orig_len = p.caplen();
  ParsedPacket parsed;
  ASSERT_EQ(parse_packet(p.data(), parsed), ParseStatus::Ok);
  fp.process(p, parsed);
  fp.finish();
  EXPECT_EQ(fp.stats().apps[static_cast<std::size_t>(AppId::DNS)].flows, 1u);
}

}  // namespace
}  // namespace dpi
