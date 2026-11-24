#pragma once

// Drives one TCP connection (client 10.0.0.1 <-> server 10.0.0.2) through a
// FastPathStage packet by packet, tracking sequence numbers and returning
// each packet's verdict.

#include <gtest/gtest.h>

#include "dpi/pipeline/stages.hpp"
#include "packet_builder.hpp"

namespace dpi::test {

class Connection {
 public:
  explicit Connection(FastPathStage& fp, std::uint16_t server_port = 443, std::uint16_t client_port = 40000,
                      std::uint32_t client_ip = ip(10, 0, 0, 1), std::uint32_t server_ip = ip(10, 0, 0, 2))
      : fp_(fp), server_port_(server_port), client_port_(client_port), client_ip_(client_ip),
        server_ip_(server_ip) {}

  // SYN, SYN-ACK, ACK. Returns the verdicts.
  std::vector<Verdict> handshake() {
    return {send(true, tcpflag::kSyn, {}), send(false, tcpflag::kSyn | tcpflag::kAck, {}),
            send(true, tcpflag::kAck, {})};
  }

  // Sends `payload` from the client with the next sequence number (or with
  // `seq_override` to simulate reordering).
  Verdict client(const Bytes& payload, std::uint32_t seq_override = 0) {
    return send(true, tcpflag::kPsh | tcpflag::kAck, payload, seq_override);
  }
  Verdict server(const Bytes& payload) { return send(false, tcpflag::kPsh | tcpflag::kAck, payload); }

  Verdict send(bool from_client, std::uint8_t flags, const Bytes& payload, std::uint32_t seq_override = 0) {
    FrameSpec s = tcp_spec(payload);
    s.tcp_flags = flags;
    s.src_ip = from_client ? client_ip_ : server_ip_;
    s.dst_ip = from_client ? server_ip_ : client_ip_;
    s.src_port = from_client ? client_port_ : server_port_;
    s.dst_port = from_client ? server_port_ : client_port_;
    std::uint32_t& seq = from_client ? client_seq_ : server_seq_;
    s.tcp_seq = seq_override != 0 ? seq_override : seq;
    if (seq_override == 0) {
      seq += static_cast<std::uint32_t>(payload.size()) + ((flags & tcpflag::kSyn) ? 1 : 0);
    }
    Packet p;
    p.bytes = build_frame(s);
    p.orig_len = p.caplen();
    ParsedPacket parsed;
    EXPECT_EQ(parse_packet(p.data(), parsed), ParseStatus::Ok);
    return fp_.process(p, parsed);
  }

 private:
  FastPathStage& fp_;
  std::uint16_t server_port_;
  std::uint16_t client_port_;
  std::uint32_t client_ip_;
  std::uint32_t server_ip_;
  std::uint32_t client_seq_ = 1000;
  std::uint32_t server_seq_ = 5000;
};

}  // namespace dpi::test
