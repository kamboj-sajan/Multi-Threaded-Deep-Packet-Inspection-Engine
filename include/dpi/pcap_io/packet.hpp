#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace dpi {

// One captured frame. Move-only on purpose: a packet is owned by exactly one
// pipeline stage at a time, and accidental copies of the payload would be a
// silent performance bug.
struct Packet {
  std::uint64_t seq = 0;       // Index of the record in the input file.
  std::uint64_t ts_ns = 0;     // Capture timestamp, nanoseconds since epoch.
  std::uint32_t orig_len = 0;  // Length on the wire (may exceed caplen).
  std::vector<std::uint8_t> bytes;  // Captured bytes; caplen == bytes.size().

  Packet() = default;
  Packet(const Packet&) = delete;
  Packet& operator=(const Packet&) = delete;
  Packet(Packet&&) noexcept = default;
  Packet& operator=(Packet&&) noexcept = default;
  ~Packet() = default;

  std::uint32_t caplen() const noexcept { return static_cast<std::uint32_t>(bytes.size()); }
  std::span<const std::uint8_t> data() const noexcept { return bytes; }

  // Explicit deep copy, for tests and the rare place that needs one.
  Packet clone() const {
    Packet copy;
    copy.seq = seq;
    copy.ts_ns = ts_ns;
    copy.orig_len = orig_len;
    copy.bytes = bytes;
    return copy;
  }
};

}  // namespace dpi
