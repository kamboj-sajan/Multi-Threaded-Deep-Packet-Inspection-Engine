#include <gtest/gtest.h>

#include <algorithm>
#include <memory>
#include <tuple>
#include <stdexcept>
#include <vector>

#include "dpi/pipeline/engine.hpp"
#include "pcap_builder.hpp"

namespace dpi {
namespace {

using test::Bytes;
using test::tcp_frame;
using test::TimedFrame;

Bytes many_packets_pcap(int n) {
  std::vector<TimedFrame> frames;
  for (int i = 0; i < n; ++i) {
    frames.push_back({static_cast<std::uint64_t>(i),
                      tcp_frame(i % 2 == 0, tcpflag::kAck, Bytes(64, 1), static_cast<std::uint16_t>(30000 + i % 50))});
  }
  return test::build_pcap(frames);
}

EngineConfig small_config() {
  EngineConfig c;
  c.num_lbs = 2;
  c.fps_per_lb = 2;
  c.queue_capacity = 2;  // tiny, so threads are blocked when the failure hits
  return c;
}

// Accepts the global header and a few records, then fails like a full disk.
class FailingSink final : public ByteSink {
 public:
  explicit FailingSink(std::size_t fail_after_writes) : remaining_(fail_after_writes) {}
  void write(std::span<const std::uint8_t>) override {
    if (remaining_-- == 0) {
      throw PcapError("simulated write failure");
    }
  }

 private:
  std::size_t remaining_;
};

// Delivers a valid file prefix, then fails like a broken disk.
class FailingSource final : public ByteSource {
 public:
  FailingSource(const Bytes& data, std::size_t fail_at) : data_(data), fail_at_(fail_at) {}
  std::size_t read(std::span<std::uint8_t> out) override {
    if (pos_ + out.size() > fail_at_) {
      throw PcapError("simulated read failure");
    }
    std::copy_n(data_.begin() + static_cast<std::ptrdiff_t>(pos_), out.size(), out.begin());
    pos_ += out.size();
    return out.size();
  }

 private:
  const Bytes& data_;
  std::size_t fail_at_;
  std::size_t pos_ = 0;
};

TEST(PipelineThreads, WriterFailureStopsEveryThreadAndIsRethrown) {
  const Bytes input = many_packets_pcap(2000);
  PcapReader reader(std::make_unique<MemorySource>(input));
  PcapWriter writer(std::make_unique<FailingSink>(20), {});
  // Would hang forever if a blocked thread were not woken on failure.
  EXPECT_THROW(run_pipeline(reader, writer, small_config()), PcapError);
}

TEST(PipelineThreads, ReaderFailureStopsEveryThreadAndIsRethrown) {
  const Bytes input = many_packets_pcap(2000);
  PcapReader reader(std::make_unique<FailingSource>(input, input.size() / 2));
  Bytes output;
  PcapWriter writer(std::make_unique<MemorySink>(output), {});
  EXPECT_THROW(run_pipeline(reader, writer, small_config()), PcapError);
}

TEST(PipelineThreads, RejectsInvalidLayouts) {
  const Bytes input = many_packets_pcap(1);
  Bytes output;
  for (const auto& [lbs, fps, queue] : std::vector<std::tuple<std::size_t, std::size_t, std::size_t>>{
           {0, 1, 1}, {1, 0, 1}, {1, 1, 0}}) {
    PcapReader reader(std::make_unique<MemorySource>(input));
    PcapWriter writer(std::make_unique<MemorySink>(output), {});
    EngineConfig c;
    c.num_lbs = lbs;
    c.fps_per_lb = fps;
    c.queue_capacity = queue;
    EXPECT_THROW(run_pipeline(reader, writer, c), std::invalid_argument);
  }
}

TEST(PipelineThreads, EmptyCaptureShutsDownCleanly) {
  const Bytes input = test::build_pcap({});
  PcapReader reader(std::make_unique<MemorySource>(input));
  Bytes output;
  PcapWriter writer(std::make_unique<MemorySink>(output), {});
  const RunStats s = run_pipeline(reader, writer, small_config());
  EXPECT_EQ(s.total_packets(), 0u);
  EXPECT_EQ(s.fps.size(), 4u);
}

}  // namespace
}  // namespace dpi
