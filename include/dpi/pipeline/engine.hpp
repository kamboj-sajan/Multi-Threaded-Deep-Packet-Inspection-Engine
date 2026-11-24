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

}  // namespace dpi
