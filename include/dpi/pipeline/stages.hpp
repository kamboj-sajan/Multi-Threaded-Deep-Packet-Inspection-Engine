#pragma once

// The four pipeline stages as plain single-threaded objects. The sequential
// baseline calls them in a loop; the threaded pipeline gives each one its
// own thread and connects them with queues. Because both modes run exactly
// this code, comparing their results is a real test of the threading.

#include <cstddef>
#include <cstdint>
#include <optional>

#include "dpi/classifier/classifier.hpp"
#include "dpi/flow/flow_table.hpp"
#include "dpi/parser/packet_parser.hpp"
#include "dpi/pcap_io/pcap_reader.hpp"
#include "dpi/pcap_io/pcap_writer.hpp"
#include "dpi/pipeline/flow_inspector.hpp"
#include "dpi/pipeline/stats.hpp"

namespace dpi {

// Direction-independent hash of a raw frame, used to route it. Frames
// without a readable IPv4 header all hash to 0 (they carry no flow).
std::uint64_t routing_hash(ByteView frame) noexcept;

// Flow affinity: the hash alone picks the load balancer and, within that
// LB's group, the fast-path worker. Dividing by num_lbs before taking the
// FP index means the two choices use different bits of the hash, so flows
// on one LB still spread over all of its FPs.
inline std::size_t lb_index(std::uint64_t hash, std::size_t num_lbs) noexcept {
  return static_cast<std::size_t>(hash % num_lbs);
}
inline std::size_t fp_index_in_group(std::uint64_t hash, std::size_t num_lbs,
                                     std::size_t fps_per_lb) noexcept {
  return static_cast<std::size_t>((hash / num_lbs) % fps_per_lb);
}

// Reader -> LB.
struct RoutedPacket {
  Packet packet;
  std::uint64_t hash = 0;
};

// LB -> FP.
struct WorkItem {
  Packet packet;
  ParsedPacket parsed;
  std::uint64_t hash = 0;
};

// Stage 1: pulls records from the PCAP and computes their routing hash.
class ReaderStage {
 public:
  explicit ReaderStage(PcapReader& reader) : reader_(reader) {}

  // Returns false at end of input. Truncated/corrupt trailing records are
  // counted in stats() rather than returned.
  bool next(RoutedPacket& out);
  const ReaderStats& stats() const noexcept { return stats_; }

 private:
  PcapReader& reader_;
  ReaderStats stats_;
};

// Stage 2: full L2-L4 decode. Malformed packets are counted and dropped
// here so the fast path only ever sees well-formed headers.
class LoadBalancerStage {
 public:
  std::optional<WorkItem> process(RoutedPacket&& in);
  const LbStats& stats() const noexcept { return stats_; }

 private:
  LbStats stats_;
};

struct FastPathConfig {
  FlowTableConfig flow_table;
  InspectionConfig inspection;
  // Shared, immutable domain table; nullptr means the built-in one.
  const Classifier* classifier = nullptr;
  // How often (in capture time) to sweep idle flows out of memory.
  std::uint64_t sweep_interval_ns = 1'000'000'000ULL;
};

// Stage 3: flow tracking, inspection and the per-packet verdict. Owns its
// FlowTable exclusively, so no flow state is shared with other threads.
// Once a flow is classified it skips inspection entirely (the fast path).
class FastPathStage {
 public:
  explicit FastPathStage(FastPathConfig config = {});
  FastPathStage(const FastPathStage&) = delete;
  FastPathStage& operator=(const FastPathStage&) = delete;

  Verdict process(const Packet& packet, const ParsedPacket& parsed);

  // Retires all remaining flows into the statistics. Call once, after the
  // last packet.
  void finish();
  const FpStats& stats() const noexcept { return stats_; }

 private:
  struct Tracked {
    FlowEntry* flow;
    bool from_client;
  };
  Tracked track_flow(const Packet& packet, const ParsedPacket& parsed);
  void record_retired_flow(const FlowEntry& flow);
  void maybe_sweep(std::uint64_t now_ns);

  FastPathConfig config_;
  FlowInspector inspector_;
  FlowTable table_;
  FpStats stats_;
  std::uint64_t next_sweep_ns_ = 0;
};

// Stage 4: appends forwarded packets to the output capture.
class WriterStage {
 public:
  explicit WriterStage(PcapWriter& writer) : writer_(writer) {}
  void write(const Packet& packet);
  void finish() { writer_.flush(); }
  const WriterStats& stats() const noexcept { return stats_; }

 private:
  PcapWriter& writer_;
  WriterStats stats_;
};

}  // namespace dpi
