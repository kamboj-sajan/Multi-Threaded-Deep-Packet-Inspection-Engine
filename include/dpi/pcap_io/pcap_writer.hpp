#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "dpi/pcap_io/byte_io.hpp"
#include "dpi/pcap_io/packet.hpp"
#include "dpi/pcap_io/pcap_format.hpp"

namespace dpi {

struct PcapWriterOptions {
  std::uint32_t snaplen = pcap::kMaxRecordLen;
  std::uint32_t linktype = pcap::kLinktypeEthernet;
  pcap::Precision precision = pcap::Precision::Micro;
};

// Writes a classic PCAP in host byte order (the convention every libpcap
// writer follows; readers detect the order from the magic number).
class PcapWriter {
 public:
  PcapWriter(std::unique_ptr<ByteSink> sink, PcapWriterOptions options);
  static PcapWriter create_file(const std::string& path, PcapWriterOptions options);

  void write(const Packet& packet);
  void flush();
  std::uint64_t packets_written() const noexcept { return packets_written_; }

 private:
  void write_global_header();

  std::unique_ptr<ByteSink> sink_;
  PcapWriterOptions options_;
  std::uint64_t packets_written_ = 0;
};

}  // namespace dpi
