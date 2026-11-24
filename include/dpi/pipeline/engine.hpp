#pragma once

#include <cstddef>

#include "dpi/pcap_io/pcap_reader.hpp"
#include "dpi/pcap_io/pcap_writer.hpp"
#include "dpi/pipeline/stages.hpp"
#include "dpi/pipeline/stats.hpp"

namespace dpi {

struct EngineConfig {
  std::size_t num_lbs = 2;
  std::size_t fps_per_lb = 2;
  std::size_t queue_capacity = 4096;
  FastPathConfig fast_path;
};

// Correctness baseline: every stage runs on the calling thread, in order,
// with one LB and one FP. The threaded pipeline must produce the same
// per-flow results as this function.
RunStats run_sequential(PcapReader& reader, PcapWriter& writer, const EngineConfig& config);

// The multithreaded engine:
//
//   reader --> LB[h % N] --> FP[(h / N) % K] of that LB --> writer
//   1 thread   N threads     N*K threads                   1 thread
//
// Flow affinity: a packet's route depends only on its flow hash, so every
// packet of a flow (both directions) visits the same LB and FP, through
// FIFO queues, and per-flow order is preserved. Packets of *different*
// flows may be written in a different order than they were read, because
// FPs run independently. Each FP owns its flow table, so no flow state is
// shared between threads.
//
// Throws std::invalid_argument for a bad config. If any stage throws (e.g.
// a write error), all queues are closed so every thread stops, all threads
// are joined, and the first exception is rethrown.
RunStats run_pipeline(PcapReader& reader, PcapWriter& writer, const EngineConfig& config);

}  // namespace dpi
