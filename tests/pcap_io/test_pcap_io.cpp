#include <gtest/gtest.h>
#include <unistd.h>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <vector>

#include "dpi/common/bytes.hpp"
#include "dpi/pcap_io/pcap_reader.hpp"
#include "dpi/pcap_io/pcap_writer.hpp"

namespace dpi {
namespace {

using Bytes = std::vector<std::uint8_t>;

Packet make_packet(std::uint64_t ts_ns, Bytes bytes, std::uint32_t orig_len = 0) {
  Packet p;
  p.ts_ns = ts_ns;
  p.orig_len = orig_len != 0 ? orig_len : static_cast<std::uint32_t>(bytes.size());
  p.bytes = std::move(bytes);
  return p;
}

PcapReader reader_over(const Bytes& data) {
  return PcapReader(std::make_unique<MemorySource>(data));
}

// Appends a 32-bit value in the requested byte order, so tests can build
// files as if written on a big- or little-endian host.
void put32(Bytes& out, std::uint32_t v, bool big_endian) {
  for (int i = 0; i < 4; ++i) {
    const int shift = big_endian ? (3 - i) * 8 : i * 8;
    out.push_back(static_cast<std::uint8_t>(v >> shift));
  }
}

void put16(Bytes& out, std::uint16_t v, bool big_endian) {
  if (big_endian) {
    out.push_back(static_cast<std::uint8_t>(v >> 8));
    out.push_back(static_cast<std::uint8_t>(v));
  } else {
    out.push_back(static_cast<std::uint8_t>(v));
    out.push_back(static_cast<std::uint8_t>(v >> 8));
  }
}

// Builds a global header with an explicit byte order. The magic is written
// as a value in that byte order, which is exactly how real writers do it.
Bytes global_header(std::uint32_t magic, bool big_endian, std::uint32_t linktype = 1) {
  Bytes out;
  put32(out, magic, big_endian);
  put16(out, 2, big_endian);
  put16(out, 4, big_endian);
  put32(out, 0, big_endian);
  put32(out, 0, big_endian);
  put32(out, 65535, big_endian);
  put32(out, linktype, big_endian);
  return out;
}

void append_record(Bytes& out, std::uint32_t sec, std::uint32_t frac, const Bytes& payload,
                   bool big_endian) {
  put32(out, sec, big_endian);
  put32(out, frac, big_endian);
  put32(out, static_cast<std::uint32_t>(payload.size()), big_endian);
  put32(out, static_cast<std::uint32_t>(payload.size()), big_endian);
  out.insert(out.end(), payload.begin(), payload.end());
}

bool host_is_big_endian() { return htonl(1) == 1; }

TEST(PcapIo, MemoryRoundTripPreservesEveryField) {
  Bytes file;
  {
    PcapWriter writer(std::make_unique<MemorySink>(file), {});
    writer.write(make_packet(1'700'000'000'123'456'000ULL, {0xde, 0xad, 0xbe, 0xef}));
    writer.write(make_packet(1'700'000'001'000'000'000ULL, Bytes(1514, 0x5a), 9000));
    writer.write(make_packet(1'700'000'002'000'001'000ULL, {}));  // caplen 0 is legal
    EXPECT_EQ(writer.packets_written(), 3u);
  }

  PcapReader reader = reader_over(file);
  EXPECT_EQ(reader.info().linktype, pcap::kLinktypeEthernet);
  EXPECT_EQ(reader.info().precision, pcap::Precision::Micro);
  EXPECT_FALSE(reader.info().byte_swapped);

  Packet p;
  ASSERT_EQ(reader.next(p), ReadStatus::Ok);
  EXPECT_EQ(p.seq, 0u);
  EXPECT_EQ(p.ts_ns, 1'700'000'000'123'456'000ULL);
  EXPECT_EQ(p.bytes, (Bytes{0xde, 0xad, 0xbe, 0xef}));

  ASSERT_EQ(reader.next(p), ReadStatus::Ok);
  EXPECT_EQ(p.seq, 1u);
  EXPECT_EQ(p.caplen(), 1514u);
  EXPECT_EQ(p.orig_len, 9000u);

  ASSERT_EQ(reader.next(p), ReadStatus::Ok);
  EXPECT_EQ(p.seq, 2u);
  EXPECT_EQ(p.caplen(), 0u);

  EXPECT_EQ(reader.next(p), ReadStatus::EndOfFile);
  EXPECT_EQ(reader.next(p), ReadStatus::EndOfFile);  // stays at EOF
}

TEST(PcapIo, NanosecondPrecisionRoundTrips) {
  Bytes file;
  {
    PcapWriter writer(std::make_unique<MemorySink>(file), {.precision = pcap::Precision::Nano});
    writer.write(make_packet(5'000'000'123ULL, {1, 2, 3}));
  }
  PcapReader reader = reader_over(file);
  EXPECT_EQ(reader.info().precision, pcap::Precision::Nano);
  Packet p;
  ASSERT_EQ(reader.next(p), ReadStatus::Ok);
  EXPECT_EQ(p.ts_ns, 5'000'000'123ULL);
}

TEST(PcapIo, MicrosecondWriterDropsSubMicrosecondDigits) {
  Bytes file;
  {
    PcapWriter writer(std::make_unique<MemorySink>(file), {});
    writer.write(make_packet(1'000'001'999ULL, {1}));
  }
  PcapReader reader = reader_over(file);
  Packet p;
  ASSERT_EQ(reader.next(p), ReadStatus::Ok);
  EXPECT_EQ(p.ts_ns, 1'000'001'000ULL);
}

TEST(PcapIo, ReadsFileFromOppositeEndianHost) {
  const bool big = !host_is_big_endian();  // opposite of ours
  Bytes file = global_header(pcap::kMagicMicro, big);
  append_record(file, 10, 20, {0xaa, 0xbb}, big);

  PcapReader reader = reader_over(file);
  EXPECT_TRUE(reader.info().byte_swapped);
  EXPECT_EQ(reader.info().snaplen, 65535u);
  EXPECT_EQ(reader.info().version_major, 2u);
  EXPECT_EQ(reader.info().version_minor, 4u);
  Packet p;
  ASSERT_EQ(reader.next(p), ReadStatus::Ok);
  EXPECT_EQ(p.ts_ns, 10'000'020'000ULL);
  EXPECT_EQ(p.bytes, (Bytes{0xaa, 0xbb}));
}

TEST(PcapIo, ReadsByteSwappedNanosecondMagic) {
  const bool big = !host_is_big_endian();
  Bytes file = global_header(pcap::kMagicNano, big);
  append_record(file, 1, 7, {0x01}, big);

  PcapReader reader = reader_over(file);
  EXPECT_TRUE(reader.info().byte_swapped);
  EXPECT_EQ(reader.info().precision, pcap::Precision::Nano);
  Packet p;
  ASSERT_EQ(reader.next(p), ReadStatus::Ok);
  EXPECT_EQ(p.ts_ns, 1'000'000'007ULL);
}

TEST(PcapIo, RejectsUnknownMagic) {
  Bytes file = global_header(0x0a0d0d0a, false);  // pcapng section header
  EXPECT_THROW(reader_over(file), PcapError);
}

TEST(PcapIo, RejectsNonEthernetLinktype) {
  Bytes file = global_header(pcap::kMagicMicro, host_is_big_endian(), 101);  // raw IP
  EXPECT_THROW(reader_over(file), PcapError);
}

TEST(PcapIo, RejectsShortGlobalHeader) {
  Bytes file = global_header(pcap::kMagicMicro, host_is_big_endian());
  file.resize(10);
  EXPECT_THROW(reader_over(file), PcapError);
  EXPECT_THROW(reader_over(Bytes{}), PcapError);
}

TEST(PcapIo, TruncatedRecordHeaderIsReportedThenStops) {
  const bool big = host_is_big_endian();
  Bytes file = global_header(pcap::kMagicMicro, big);
  append_record(file, 1, 0, {1, 2, 3}, big);
  file.insert(file.end(), {0, 0, 0, 0, 0});  // 5 of 16 header bytes

  PcapReader reader = reader_over(file);
  Packet p;
  EXPECT_EQ(reader.next(p), ReadStatus::Ok);
  EXPECT_EQ(reader.next(p), ReadStatus::TruncatedRecord);
  EXPECT_EQ(reader.next(p), ReadStatus::EndOfFile);
}

TEST(PcapIo, TruncatedRecordBodyIsReported) {
  const bool big = host_is_big_endian();
  Bytes file = global_header(pcap::kMagicMicro, big);
  append_record(file, 1, 0, Bytes(100, 7), big);
  file.resize(file.size() - 40);  // cut the body short

  PcapReader reader = reader_over(file);
  Packet p;
  EXPECT_EQ(reader.next(p), ReadStatus::TruncatedRecord);
  EXPECT_EQ(reader.next(p), ReadStatus::EndOfFile);
}

TEST(PcapIo, OversizedCaplenIsCorruptAndNotAllocated) {
  const bool big = host_is_big_endian();
  Bytes file = global_header(pcap::kMagicMicro, big);
  put32(file, 1, big);
  put32(file, 0, big);
  put32(file, 0xFFFFFFF0u, big);  // hostile caplen
  put32(file, 64, big);

  PcapReader reader = reader_over(file);
  Packet p;
  EXPECT_EQ(reader.next(p), ReadStatus::CorruptRecord);
  EXPECT_TRUE(p.bytes.empty());
  EXPECT_EQ(reader.next(p), ReadStatus::EndOfFile);
}

TEST(PcapIo, FileRoundTrip) {
  const auto path = std::filesystem::temp_directory_path() /
                    ("dpi_pcap_io_roundtrip_" + std::to_string(::getpid()) + ".pcap");
  {
    PcapWriter writer = PcapWriter::create_file(path.string(), {});
    for (std::uint8_t i = 0; i < 50; ++i) {
      writer.write(make_packet(1'000'000'000ULL * i, Bytes(60 + i, i)));
    }
    writer.flush();
  }

  PcapReader reader = PcapReader::open_file(path.string());
  Packet p;
  std::uint64_t count = 0;
  while (reader.next(p) == ReadStatus::Ok) {
    EXPECT_EQ(p.seq, count);
    EXPECT_EQ(p.caplen(), 60 + count);
    EXPECT_EQ(p.bytes.front(), static_cast<std::uint8_t>(count));
    ++count;
  }
  EXPECT_EQ(count, 50u);
  std::filesystem::remove(path);
}

TEST(PcapIo, OpeningMissingFileThrows) {
  EXPECT_THROW(PcapReader::open_file("/nonexistent/dir/capture.pcap"), PcapError);
}

TEST(PcapIo, ReadWholeFileMatchesWriterOutput) {
  const auto path = std::filesystem::temp_directory_path() /
                    ("dpi_pcap_io_whole_" + std::to_string(::getpid()) + ".pcap");
  Bytes in_memory;
  {
    PcapWriter file_writer = PcapWriter::create_file(path.string(), {});
    PcapWriter mem_writer(std::make_unique<MemorySink>(in_memory), {});
    for (std::uint8_t i = 0; i < 5; ++i) {
      file_writer.write(make_packet(i, Bytes(10, i)));
      mem_writer.write(make_packet(i, Bytes(10, i)));
    }
  }
  EXPECT_EQ(read_whole_file(path.string()), in_memory);
  std::filesystem::remove(path);
}

}  // namespace
}  // namespace dpi
