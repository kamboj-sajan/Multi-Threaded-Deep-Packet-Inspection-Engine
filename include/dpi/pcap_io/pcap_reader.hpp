#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "dpi/pcap_io/byte_io.hpp"
#include "dpi/pcap_io/packet.hpp"
#include "dpi/pcap_io/pcap_format.hpp"

namespace dpi {

struct PcapFileInfo {
  std::uint16_t version_major = 0;
  std::uint16_t version_minor = 0;
  std::uint32_t snaplen = 0;
  std::uint32_t linktype = 0;
  pcap::Precision precision = pcap::Precision::Micro;
  bool byte_swapped = false;  // File was written on an opposite-endian host.
};

enum class ReadStatus {
  Ok,               // `out` holds the next packet.
  EndOfFile,        // Clean end of input.
  TruncatedRecord,  // Input ended inside a record (count it as malformed).
  CorruptRecord,    // Record header is nonsensical; cannot resynchronise.
};

// Streams records out of a classic PCAP file.
//
// The constructor validates the global header and throws PcapError if the
// file is not an Ethernet PCAP. After a Truncated/Corrupt status the reader
// stops and further calls return EndOfFile, because there is no reliable
// way to find the next record boundary.
class PcapReader {
 public:
  explicit PcapReader(std::unique_ptr<ByteSource> source);
  static PcapReader open_file(const std::string& path);

  const PcapFileInfo& info() const noexcept { return info_; }
  ReadStatus next(Packet& out);
  std::uint64_t records_read() const noexcept { return next_seq_; }

 private:
  void read_global_header();
  std::uint32_t to_host(std::uint32_t v) const noexcept;
  std::uint16_t to_host(std::uint16_t v) const noexcept;

  std::unique_ptr<ByteSource> source_;
  PcapFileInfo info_;
  std::uint64_t next_seq_ = 0;
  bool done_ = false;
};

}  // namespace dpi
