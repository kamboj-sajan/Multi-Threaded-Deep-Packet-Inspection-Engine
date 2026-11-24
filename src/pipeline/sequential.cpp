#include <chrono>

#include "dpi/pipeline/engine.hpp"

namespace dpi {

RunStats run_sequential(PcapReader& reader, PcapWriter& writer, const EngineConfig& config) {
  const auto start = std::chrono::steady_clock::now();

  ReaderStage reader_stage(reader);
  LoadBalancerStage lb_stage;
  FastPathStage fp_stage(config.fast_path);
  WriterStage writer_stage(writer);

  RoutedPacket routed;
  while (reader_stage.next(routed)) {
    std::optional<WorkItem> item = lb_stage.process(std::move(routed));
    if (item && fp_stage.process(item->packet, item->parsed) == Verdict::Forward) {
      writer_stage.write(item->packet);
    }
  }
  fp_stage.finish();
  writer_stage.finish();

  RunStats stats;
  stats.num_lbs = 1;
  stats.fps_per_lb = 1;
  stats.reader = reader_stage.stats();
  stats.lbs.push_back(lb_stage.stats());
  stats.fps.push_back(fp_stage.stats());
  stats.writer = writer_stage.stats();
  stats.elapsed_seconds =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
  return stats;
}

}  // namespace dpi
