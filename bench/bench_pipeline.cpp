// Pipeline throughput benchmark.
//
// The capture is read into memory once, before any timing, and the output
// goes to a NullSink, so the numbers measure the engine rather than the
// disk. Each layout runs `--repeats` times after one warm-up run; the
// table reports the median, with min and max for spread.
//
// usage: bench_pipeline <capture.pcap> [--repeats N] [--rules FILE] [--queue-size N] [--batch-size N]

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "dpi/pcap_io/byte_io.hpp"
#include "dpi/pcap_io/pcap_reader.hpp"
#include "dpi/pcap_io/pcap_writer.hpp"
#include "dpi/pipeline/engine.hpp"
#include "dpi/rules/rule_set.hpp"

namespace {

struct Layout {
  const char* name;
  bool sequential;
  std::size_t lbs;
  std::size_t fps_per_lb;
};

struct Sample {
  double seconds;
  std::uint64_t packets;
  std::uint64_t bytes;
  std::uint64_t forwarded;
};

Sample run_once(const std::vector<std::uint8_t>& capture, const Layout& layout, const dpi::EngineConfig& base) {
  dpi::PcapReader reader(std::make_unique<dpi::MemorySource>(capture));
  dpi::PcapWriter writer(std::make_unique<dpi::NullSink>(), {.precision = reader.info().precision});
  dpi::EngineConfig config = base;
  config.num_lbs = layout.lbs;
  config.fps_per_lb = layout.fps_per_lb;
  const dpi::RunStats s =
      layout.sequential ? dpi::run_sequential(reader, writer, config) : dpi::run_pipeline(reader, writer, config);
  return {s.elapsed_seconds, s.total_packets(), s.reader.bytes, s.forwarded()};
}

// Upper bound for the whole pipeline: the single reader thread alone
// (read record, copy into a Packet, peek 5-tuple, hash), with nothing
// downstream.
double reader_only_mpps(const std::vector<std::uint8_t>& capture) {
  dpi::PcapReader reader(std::make_unique<dpi::MemorySource>(capture));
  dpi::ReaderStage stage(reader);
  dpi::RoutedPacket routed;
  std::uint64_t checksum = 0;
  const auto start = std::chrono::steady_clock::now();
  while (stage.next(routed)) {
    checksum += routed.hash;
    routed.packet = dpi::Packet{};  // release the buffer, as the writer would
  }
  const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
  if (checksum == 42) {
    std::puts("");  // keeps the loop from being optimised away
  }
  return static_cast<double>(stage.stats().packets) / seconds / 1e6;
}

double median(std::vector<double> v) {
  std::sort(v.begin(), v.end());
  const std::size_t n = v.size();
  return n % 2 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2.0;
}

[[noreturn]] void usage() {
  std::cerr << "usage: bench_pipeline <capture.pcap> [--repeats N] [--rules FILE] [--queue-size N] [--batch-size N]\n";
  std::exit(2);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    usage();
  }
  const std::string path = argv[1];
  int repeats = 5;
  dpi::EngineConfig base;
  std::string rules_path;
  for (int i = 2; i < argc; ++i) {
    const std::string arg = argv[i];
    if (i + 1 >= argc) {
      usage();
    }
    if (arg == "--repeats") {
      repeats = std::max(1, std::atoi(argv[++i]));
    } else if (arg == "--rules") {
      rules_path = argv[++i];
      base.fast_path.rules = dpi::RuleSet::load_file(rules_path);
    } else if (arg == "--batch-size") {
      base.batch_size = static_cast<std::size_t>(std::max(1, std::atoi(argv[++i])));
    } else if (arg == "--queue-size") {
      base.queue_capacity = static_cast<std::size_t>(std::max(1, std::atoi(argv[++i])));
    } else {
      usage();
    }
  }

  std::cerr << "loading " << path << " into memory...\n";
  const std::vector<std::uint8_t> capture = dpi::read_whole_file(path);

  const std::vector<Layout> layouts = {
      {"sequential (1 thread)", true, 1, 1},
      {"1 LB x 1 FP", false, 1, 1},
      {"1 LB x 2 FP", false, 1, 2},
      {"2 LB x 2 FP", false, 2, 2},
      {"2 LB x 4 FP", false, 2, 4},
      {"1 LB x 4 FP", false, 1, 4},
      {"4 LB x 2 FP", false, 4, 2},
  };

  std::printf(
      "capture: %s (%.1f MB), hardware threads: %u, queue size: %zu, batch size: %zu, rules: %s, "
      "repeats: %d (median)\n\n",
      path.c_str(), static_cast<double>(capture.size()) / 1e6, std::thread::hardware_concurrency(),
      base.queue_capacity, base.batch_size, rules_path.empty() ? "none" : rules_path.c_str(), repeats);
  std::printf("| Layout | FP threads | Threads total | Mpps | Gbps | Mpps min-max |\n");
  std::printf("|---|---:|---:|---:|---:|---:|\n");

  std::uint64_t expected_forwarded = 0;
  for (const Layout& layout : layouts) {
    run_once(capture, layout, base);  // warm-up: page in the buffer, warm caches and the allocator
    std::vector<double> mpps;
    std::vector<double> gbps;
    for (int r = 0; r < repeats; ++r) {
      const Sample s = run_once(capture, layout, base);
      // Every layout must reach the same verdicts, or the timing is meaningless.
      if (expected_forwarded == 0) {
        expected_forwarded = s.forwarded;
      } else if (s.forwarded != expected_forwarded) {
        std::cerr << "error: " << layout.name << " forwarded " << s.forwarded << ", expected "
                  << expected_forwarded << '\n';
        return 1;
      }
      mpps.push_back(static_cast<double>(s.packets) / s.seconds / 1e6);
      gbps.push_back(static_cast<double>(s.bytes) * 8.0 / s.seconds / 1e9);
    }
    const std::size_t fps = layout.lbs * layout.fps_per_lb;
    const std::size_t threads = layout.sequential ? 1 : 2 + layout.lbs + fps;
    std::printf("| %s | %zu | %zu | %.2f | %.2f | %.2f-%.2f |\n", layout.name, fps, threads, median(mpps),
                median(gbps), *std::min_element(mpps.begin(), mpps.end()),
                *std::max_element(mpps.begin(), mpps.end()));
    std::fflush(stdout);
  }

  std::vector<double> reader;
  for (int r = 0; r < repeats + 1; ++r) {
    reader.push_back(reader_only_mpps(capture));
  }
  reader.erase(reader.begin());  // drop the warm-up run
  std::printf("\nreader stage alone (upper bound for any layout): %.2f Mpps (median)\n", median(reader));
  return 0;
}
