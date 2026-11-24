#pragma once

#include <optional>
#include <string>
#include <vector>

namespace dpi {

struct CliOptions {
  std::string input_path;
  std::string output_path;
  std::optional<std::string> report_path;
};

struct CliParseResult {
  std::optional<CliOptions> options;  // Set on success.
  bool show_help = false;
  std::string error;                  // Set on failure.
};

// Parses argv[1..]. Kept free of I/O so it can be unit-tested.
CliParseResult parse_cli(const std::vector<std::string>& args);

std::string usage_text();

}  // namespace dpi
