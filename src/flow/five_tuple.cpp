#include "dpi/flow/five_tuple.hpp"

namespace dpi {
namespace {

constexpr std::uint64_t kFnvOffsetBasis = 0xcbf29ce484222325ULL;
constexpr std::uint64_t kFnvPrime = 0x100000001b3ULL;

// Feeds `bytes` bytes of `value`, most significant first.
template <typename T>
std::uint64_t fnv1a_mix(std::uint64_t hash, T value) noexcept {
  for (int shift = (static_cast<int>(sizeof(T)) - 1) * 8; shift >= 0; shift -= 8) {
    hash ^= static_cast<std::uint8_t>(value >> shift);
    hash *= kFnvPrime;
  }
  return hash;
}

// MurmurHash3's 64-bit finaliser. FNV-1a's low bits depend weakly on the
// last input bytes; since workers are chosen with `hash % N`, every output
// bit must depend on every input bit.
constexpr std::uint64_t avalanche(std::uint64_t h) noexcept {
  h ^= h >> 33;
  h *= 0xff51afd7ed558ccdULL;
  h ^= h >> 33;
  h *= 0xc4ceb9fe1a85ec53ULL;
  h ^= h >> 33;
  return h;
}

}  // namespace

NormalizedTuple normalize(const PacketTuple& t) noexcept {
  // Compare whole endpoints (ip, then port) so that two connections between
  // the same hosts on different ports stay distinct.
  const bool src_is_lo =
      t.src_ip < t.dst_ip || (t.src_ip == t.dst_ip && t.src_port <= t.dst_port);
  NormalizedTuple n;
  n.key.protocol = t.protocol;
  if (src_is_lo) {
    n.key.ip_lo = t.src_ip;
    n.key.port_lo = t.src_port;
    n.key.ip_hi = t.dst_ip;
    n.key.port_hi = t.dst_port;
    n.direction = Direction::LoToHi;
  } else {
    n.key.ip_lo = t.dst_ip;
    n.key.port_lo = t.dst_port;
    n.key.ip_hi = t.src_ip;
    n.key.port_hi = t.src_port;
    n.direction = Direction::HiToLo;
  }
  return n;
}

std::uint64_t flow_hash(const FiveTuple& key) noexcept {
  std::uint64_t h = kFnvOffsetBasis;
  h = fnv1a_mix(h, key.ip_lo);
  h = fnv1a_mix(h, key.ip_hi);
  h = fnv1a_mix(h, key.port_lo);
  h = fnv1a_mix(h, key.port_hi);
  h = fnv1a_mix(h, key.protocol);
  return avalanche(h);
}

std::string ipv4_to_string(std::uint32_t ip) {
  return std::to_string(ip >> 24) + '.' + std::to_string((ip >> 16) & 0xFF) + '.' +
         std::to_string((ip >> 8) & 0xFF) + '.' + std::to_string(ip & 0xFF);
}

std::string to_string(const FiveTuple& key) {
  return ipv4_to_string(key.ip_lo) + ':' + std::to_string(key.port_lo) + " <-> " +
         ipv4_to_string(key.ip_hi) + ':' + std::to_string(key.port_hi) + " proto " +
         std::to_string(key.protocol);
}

}  // namespace dpi
