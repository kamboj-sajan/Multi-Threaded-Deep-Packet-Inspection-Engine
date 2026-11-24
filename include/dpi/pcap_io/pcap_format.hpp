#pragma once

// Constants of the classic libpcap file format.
// Reference: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcap-03.html

#include <cstddef>
#include <cstdint>

namespace dpi::pcap {

inline constexpr std::uint32_t kMagicMicro = 0xa1b2c3d4;
inline constexpr std::uint32_t kMagicMicroSwapped = 0xd4c3b2a1;
inline constexpr std::uint32_t kMagicNano = 0xa1b23c4d;
inline constexpr std::uint32_t kMagicNanoSwapped = 0x4d3cb2a1;

inline constexpr std::size_t kGlobalHeaderLen = 24;
inline constexpr std::size_t kRecordHeaderLen = 16;

inline constexpr std::uint32_t kLinktypeEthernet = 1;

// tcpdump's own upper bound on a record. Anything larger means the file is
// corrupt (or hostile) and we must not allocate it.
inline constexpr std::uint32_t kMaxRecordLen = 262144;

enum class Precision { Micro, Nano };

}  // namespace dpi::pcap
