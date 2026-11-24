#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace dpi {

struct CliOptions {
  std::string input_path;
  std::string output_path;
  std::optional<std::string> report_path;
  std::optional<std::string> rules_path;
  std::size_t num_lbs = 2;
  std::size_t fps_per_lb = 2;
  std::size_t queue_size = 4096;
  std::size_t batch_size = 64;
  bool sequential = false;  // Run the single-threaded baseline instead.
};

// Upper bounds that catch typos ("--lbs 200") before spawning threads.
inline constexpr std::size_t kMaxLbs = 64;
inline constexpr std::size_t kMaxFpsPerLb = 64;
inline constexpr std::size_t kMaxQueueSize = 1u << 20;
inline constexpr std::size_t kMaxBatchSize = 4096;

struct CliParseResult {
  std::optional<CliOptions> options;  // Set on success.
  bool show_help = false;
  std::string error;                  // Set on failure.
};

// Parses argv[1..]. Kept free of I/O so it can be unit-tested.
CliParseResult parse_cli(const std::vector<std::string>& args);

std::string usage_text();

}  // namespace dpi
