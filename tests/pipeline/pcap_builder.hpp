#pragma once

// Builds an in-memory PCAP file from frames, for engine-level tests.

#include <memory>
#include <vector>

#include "dpi/pcap_io/pcap_writer.hpp"
#include "packet_builder.hpp"

namespace dpi::test {

struct TimedFrame {
  std::uint64_t ts_ns;
  Bytes frame;
  std::uint32_t orig_len = 0;  // 0 = same as frame size
};

inline Bytes build_pcap(const std::vector<TimedFrame>& frames) {
  Bytes file;
  PcapWriter writer(std::make_unique<MemorySink>(file), {.precision = pcap::Precision::Nano});
  for (const TimedFrame& f : frames) {
    Packet p;
    p.ts_ns = f.ts_ns;
    p.orig_len = f.orig_len != 0 ? f.orig_len : static_cast<std::uint32_t>(f.frame.size());
    p.bytes = f.frame;
    writer.write(p);
  }
  return file;
}

// A TCP packet between client 10.0.0.1:40000 and server 10.0.0.2:443.
inline Bytes tcp_frame(bool from_client, std::uint8_t flags, Bytes payload = {},
                       std::uint16_t client_port = 40000) {
  FrameSpec s = tcp_spec(std::move(payload));
  s.tcp_flags = flags;
  s.src_ip = from_client ? ip(10, 0, 0, 1) : ip(10, 0, 0, 2);
  s.dst_ip = from_client ? ip(10, 0, 0, 2) : ip(10, 0, 0, 1);
  s.src_port = from_client ? client_port : 443;
  s.dst_port = from_client ? 443 : client_port;
  return build_frame(s);
}

}  // namespace dpi::test
