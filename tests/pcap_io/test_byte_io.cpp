#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <vector>

#include "dpi/common/bytes.hpp"
#include "dpi/pcap_io/byte_io.hpp"

namespace dpi {
namespace {

TEST(Bytes, BigEndianLoadsWorkAtUnalignedOffsets) {
  const std::array<std::uint8_t, 7> raw{0xff, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc};
  const ByteView view(raw);
  EXPECT_EQ(load_u8(view, 0), 0xff);
  EXPECT_EQ(load_be16(view, 1), 0x1234);  // odd offset: unaligned
  EXPECT_EQ(load_be32(view, 1), 0x12345678u);
  EXPECT_EQ(load_be32(view, 3), 0x56789abcu);
}

TEST(Bytes, ByteSwapReversesOrder) {
  EXPECT_EQ(byteswap16(0x1234), 0x3412);
  EXPECT_EQ(byteswap32(0x11223344u), 0x44332211u);
}

TEST(ByteIo, MemorySourceReadsInChunksAndReportsShortReadAtEnd) {
  const std::vector<std::uint8_t> data{1, 2, 3, 4, 5};
  MemorySource source(data);
  std::array<std::uint8_t, 2> buf{};
  EXPECT_EQ(source.read(buf), 2u);
  EXPECT_EQ(buf[1], 2);
  EXPECT_EQ(source.read(buf), 2u);
  EXPECT_EQ(source.read(buf), 1u);
  EXPECT_EQ(buf[0], 5);
  EXPECT_EQ(source.read(buf), 0u);
}

TEST(ByteIo, MemorySinkAppendsAndNullSinkCounts) {
  std::vector<std::uint8_t> out;
  MemorySink sink(out);
  const std::array<std::uint8_t, 3> a{1, 2, 3};
  sink.write(a);
  sink.write(a);
  EXPECT_EQ(out.size(), 6u);

  NullSink null;
  null.write(a);
  EXPECT_EQ(null.bytes_written(), 3u);
}

TEST(ByteIo, MissingFileThrows) {
  EXPECT_THROW(FileSource("/nonexistent/dir/file.bin"), PcapError);
  EXPECT_THROW(FileSink("/nonexistent/dir/file.bin"), PcapError);
}

}  // namespace
}  // namespace dpi
