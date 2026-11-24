// libFuzzer target for the L2-L4 parser.
//
// Beyond "does not crash" (ASan/UBSan catch over-reads and UB), it checks
// two properties the rest of the engine relies on:
//   1. an accepted packet's payload lies inside the frame;
//   2. peek_tuple (used by the reader to route) agrees with the full
//      parser for every IPv4 packet the parser accepts - flow affinity
//      depends on it.

#include <cstddef>
#include <cstdint>

#include "dpi/parser/packet_parser.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const dpi::ByteView frame(data, size);
  const auto wire_len = static_cast<std::uint32_t>(size);

  // As a complete capture...
  dpi::ParsedPacket parsed;
  if (dpi::parse_packet(frame, wire_len, parsed) == dpi::ParseStatus::Ok) {
    if (parsed.payload_offset + parsed.payload_len > size) {
      __builtin_trap();
    }
    if (parsed.l3 == dpi::L3Kind::Ipv4) {
      const auto peeked = dpi::peek_tuple(frame);
      if (!peeked || !(*peeked == parsed.tuple())) {
        __builtin_trap();
      }
    }
  }

  // ...and as one cut short by snaplen.
  dpi::ParsedPacket truncated;
  if (dpi::parse_packet(frame, wire_len + 1000, truncated) == dpi::ParseStatus::Ok &&
      truncated.payload_offset + truncated.payload_len > size) {
    __builtin_trap();
  }
  return 0;
}
