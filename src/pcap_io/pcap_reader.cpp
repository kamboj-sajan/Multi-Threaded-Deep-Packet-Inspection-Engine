#include "dpi/pcap_io/pcap_reader.hpp"

#include <array>

#include "dpi/common/bytes.hpp"

namespace dpi {

PcapReader::PcapReader(std::unique_ptr<ByteSource> source) : source_(std::move(source)) {
  read_global_header();
}

PcapReader PcapReader::open_file(const std::string& path) {
  return PcapReader(std::make_unique<FileSource>(path));
}

std::uint32_t PcapReader::to_host(std::uint32_t v) const noexcept {
  return info_.byte_swapped ? byteswap32(v) : v;
}

std::uint16_t PcapReader::to_host(std::uint16_t v) const noexcept {
  return info_.byte_swapped ? byteswap16(v) : v;
}

void PcapReader::read_global_header() {
  std::array<std::uint8_t, pcap::kGlobalHeaderLen> raw{};
  if (source_->read(raw) != raw.size()) {
    throw PcapError("input is too short to contain a PCAP global header");
  }
  const ByteView header(raw);

  // The magic number tells us both the timestamp precision and whether the
  // writer's byte order differs from ours.
  switch (load_host32(header, 0)) {
    case pcap::kMagicMicro:
      break;
    case pcap::kMagicMicroSwapped:
      info_.byte_swapped = true;
      break;
    case pcap::kMagicNano:
      info_.precision = pcap::Precision::Nano;
      break;
    case pcap::kMagicNanoSwapped:
      info_.precision = pcap::Precision::Nano;
      info_.byte_swapped = true;
      break;
    default:
      throw PcapError("not a PCAP file (unknown magic number); pcapng is not supported");
  }

  // Layout: magic(4) version_major(2) version_minor(2) thiszone(4)
  //         sigfigs(4) snaplen(4) linktype(4)
  info_.version_major = to_host(load_host16(header, 4));
  info_.version_minor = to_host(load_host16(header, 6));
  info_.snaplen = to_host(load_host32(header, 16));
  info_.linktype = to_host(load_host32(header, 20));

  if (info_.linktype != pcap::kLinktypeEthernet) {
    throw PcapError("unsupported link type " + std::to_string(info_.linktype) +
                    " (only Ethernet, link type 1, is supported)");
  }
}

ReadStatus PcapReader::next(Packet& out) {
  if (done_) {
    return ReadStatus::EndOfFile;
  }

  std::array<std::uint8_t, pcap::kRecordHeaderLen> raw{};
  const std::size_t got = source_->read(raw);
  if (got == 0) {
    done_ = true;
    return ReadStatus::EndOfFile;
  }
  if (got < raw.size()) {
    done_ = true;
    return ReadStatus::TruncatedRecord;
  }

  // Layout: ts_sec(4) ts_frac(4) caplen(4) origlen(4)
  const ByteView header(raw);
  const std::uint64_t ts_sec = to_host(load_host32(header, 0));
  const std::uint64_t ts_frac = to_host(load_host32(header, 4));
  const std::uint32_t caplen = to_host(load_host32(header, 8));
  const std::uint32_t orig_len = to_host(load_host32(header, 12));

  // Refuse to allocate an absurd length taken from untrusted input.
  if (caplen > pcap::kMaxRecordLen) {
    done_ = true;
    return ReadStatus::CorruptRecord;
  }

  out.seq = next_seq_++;
  const std::uint64_t frac_to_ns = info_.precision == pcap::Precision::Nano ? 1 : 1000;
  out.ts_ns = ts_sec * 1'000'000'000ULL + ts_frac * frac_to_ns;
  out.orig_len = orig_len;
  out.bytes.resize(caplen);
  if (source_->read(out.bytes) != caplen) {
    done_ = true;
    return ReadStatus::TruncatedRecord;
  }
  return ReadStatus::Ok;
}

}  // namespace dpi
