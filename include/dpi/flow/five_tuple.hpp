#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "dpi/parser/parsed_packet.hpp"

namespace dpi {

// Direction-independent flow key. The endpoint (ip, port) that compares
// smaller is always stored first, so A->B and B->A produce the same key.
struct FiveTuple {
  std::uint32_t ip_lo = 0;
  std::uint32_t ip_hi = 0;
  std::uint16_t port_lo = 0;
  std::uint16_t port_hi = 0;
  std::uint8_t protocol = 0;

  bool operator==(const FiveTuple&) const = default;
};

// Which way a packet travelled relative to the normalised key.
enum class Direction : std::uint8_t {
  LoToHi,  // from (ip_lo, port_lo) to (ip_hi, port_hi)
  HiToLo,
};

inline constexpr Direction opposite(Direction d) noexcept {
  return d == Direction::LoToHi ? Direction::HiToLo : Direction::LoToHi;
}

struct NormalizedTuple {
  FiveTuple key;
  Direction direction = Direction::LoToHi;
};

NormalizedTuple normalize(const PacketTuple& t) noexcept;

// 64-bit FNV-1a over the key fields, followed by a avalanche finaliser.
// Defined over field values in a fixed byte order (not over the struct's
// memory), so it is independent of padding and of host endianness: the
// same capture is routed identically on every machine.
std::uint64_t flow_hash(const FiveTuple& key) noexcept;

struct FiveTupleHash {
  std::size_t operator()(const FiveTuple& key) const noexcept {
    return static_cast<std::size_t>(flow_hash(key));
  }
};

std::string ipv4_to_string(std::uint32_t ip);
std::string to_string(const FiveTuple& key);

}  // namespace dpi
