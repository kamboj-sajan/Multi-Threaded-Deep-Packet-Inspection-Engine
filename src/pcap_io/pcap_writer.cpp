#include "dpi/pcap_io/pcap_writer.hpp"

#include <array>
#include <cstring>
#include <type_traits>

namespace dpi {
namespace {

// Writes `value` in host byte order at `offset`.
template <typename T, std::size_t N>
void store_host(std::array<std::uint8_t, N>& buf, std::size_t offset, T value) {
  static_assert(std::is_trivially_copyable_v<T>);
  std::memcpy(buf.data() + offset, &value, sizeof value);
}

}  // namespace

PcapWriter::PcapWriter(std::unique_ptr<ByteSink> sink, PcapWriterOptions options)
    : sink_(std::move(sink)), options_(options) {
  write_global_header();
}

PcapWriter PcapWriter::create_file(const std::string& path, PcapWriterOptions options) {
  return PcapWriter(std::make_unique<FileSink>(path), options);
}

void PcapWriter::write_global_header() {
  std::array<std::uint8_t, pcap::kGlobalHeaderLen> header{};
  const std::uint32_t magic =
      options_.precision == pcap::Precision::Nano ? pcap::kMagicNano : pcap::kMagicMicro;
  store_host(header, 0, magic);
  store_host(header, 4, std::uint16_t{2});  // version_major
  store_host(header, 6, std::uint16_t{4});  // version_minor
  store_host(header, 8, std::uint32_t{0});  // thiszone: timestamps are UTC
  store_host(header, 12, std::uint32_t{0});  // sigfigs: unused by readers
  store_host(header, 16, options_.snaplen);
  store_host(header, 20, options_.linktype);
  sink_->write(header);
}

void PcapWriter::write(const Packet& packet) {
  std::array<std::uint8_t, pcap::kRecordHeaderLen> header{};
  const bool nano = options_.precision == pcap::Precision::Nano;
  const auto ts_sec = static_cast<std::uint32_t>(packet.ts_ns / 1'000'000'000ULL);
  const std::uint64_t ns_part = packet.ts_ns % 1'000'000'000ULL;
  const auto ts_frac = static_cast<std::uint32_t>(nano ? ns_part : ns_part / 1000);

  store_host(header, 0, ts_sec);
  store_host(header, 4, ts_frac);
  store_host(header, 8, packet.caplen());
  store_host(header, 12, packet.orig_len);
  sink_->write(header);
  sink_->write(packet.data());
  ++packets_written_;
}

void PcapWriter::flush() { sink_->flush(); }

}  // namespace dpi
