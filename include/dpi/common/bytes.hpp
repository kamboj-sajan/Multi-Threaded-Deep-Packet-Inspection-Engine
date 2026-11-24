#pragma once

// Helpers for reading multi-byte integers out of raw packet buffers.
//
// Packet bytes have no alignment guarantee, so casting a pointer to
// uint16_t* would be undefined behaviour. Every multi-byte read therefore
// goes through memcpy, which compilers lower to a single load.
//
// These functions do NOT bounds-check in release builds: callers check the
// whole header length once before reading its fields. The assert catches a
// missing check in debug and sanitizer builds.

#include <arpa/inet.h>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace dpi {

using ByteView = std::span<const std::uint8_t>;

inline std::uint8_t load_u8(ByteView data, std::size_t offset) noexcept {
  assert(offset < data.size());
  return data[offset];
}

// Network (big-endian) 16-bit read.
inline std::uint16_t load_be16(ByteView data, std::size_t offset) noexcept {
  assert(offset + sizeof(std::uint16_t) <= data.size());
  std::uint16_t value;
  std::memcpy(&value, data.data() + offset, sizeof value);
  return ntohs(value);
}

// Network (big-endian) 32-bit read.
inline std::uint32_t load_be32(ByteView data, std::size_t offset) noexcept {
  assert(offset + sizeof(std::uint32_t) <= data.size());
  std::uint32_t value;
  std::memcpy(&value, data.data() + offset, sizeof value);
  return ntohl(value);
}

// Host-order read, used for PCAP headers, which are stored in the byte
// order of the machine that wrote the file.
inline std::uint32_t load_host32(ByteView data, std::size_t offset) noexcept {
  assert(offset + sizeof(std::uint32_t) <= data.size());
  std::uint32_t value;
  std::memcpy(&value, data.data() + offset, sizeof value);
  return value;
}

inline std::uint16_t load_host16(ByteView data, std::size_t offset) noexcept {
  assert(offset + sizeof(std::uint16_t) <= data.size());
  std::uint16_t value;
  std::memcpy(&value, data.data() + offset, sizeof value);
  return value;
}

inline std::uint16_t byteswap16(std::uint16_t v) noexcept { return __builtin_bswap16(v); }
inline std::uint32_t byteswap32(std::uint32_t v) noexcept { return __builtin_bswap32(v); }

}  // namespace dpi
