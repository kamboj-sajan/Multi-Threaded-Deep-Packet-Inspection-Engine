#include "dpi/app/cli.hpp"

#include <charconv>

namespace dpi {
namespace {

// Parses a decimal count in [1, max]; std::stoul would accept "-1" and "3x".
std::optional<std::size_t> parse_count(const std::string& text, std::size_t max) {
  std::size_t value = 0;
  const char* end = text.data() + text.size();
  const auto [ptr, ec] = std::from_chars(text.data(), end, value);
  if (ec != std::errc{} || ptr != end || value == 0 || value > max) {
    return std::nullopt;
  }
  return value;
}

}  // namespace

std::string usage_text() {
  return "usage: dpi_engine <input.pcap> <output.pcap> [options]\n"
         "\n"
         "Reads an Ethernet PCAP, inspects every flow, writes the forwarded\n"
         "packets to <output.pcap> and prints a statistics report.\n"
         "\n"
         "options:\n"
         "  --lbs <n>            load-balancer threads (default 2)\n"
         "  --fps-per-lb <n>     fast-path threads per load balancer (default 2)\n"
         "  --queue-size <n>     packets each inter-thread queue holds (default 4096)\n"
         "  --batch-size <n>     packets handed between threads at once (default 64)\n"
         "  --sequential         run every stage on one thread (correctness baseline)\n"
         "  --rules <file>       blocking rules, e.g. rules/example_rules.txt\n"
         "  --report <file>      also write the report as JSON\n"
         "  -h, --help           show this help\n";
}

CliParseResult parse_cli(const std::vector<std::string>& args) {
  CliParseResult result;
  CliOptions options;
  std::vector<std::string> positional;

  for (std::size_t i = 0; i < args.size(); ++i) {
    const std::string& arg = args[i];
    // Fetches the value of an option that takes one, or records an error.
    auto value = [&]() -> std::optional<std::string> {
      if (i + 1 >= args.size()) {
        result.error = "missing value for " + arg;
        return std::nullopt;
      }
      return args[++i];
    };

    if (arg == "-h" || arg == "--help") {
      result.show_help = true;
      return result;
    }
    // Parses the value of a numeric option into `target`.
    auto count = [&](std::size_t& target, std::size_t max) {
      const auto v = value();
      if (!v) {
        return false;
      }
      const auto n = parse_count(*v, max);
      if (!n) {
        result.error = arg + " expects a whole number from 1 to " + std::to_string(max) + ", got '" + *v + "'";
        return false;
      }
      target = *n;
      return true;
    };

    if (arg == "--rules") {
      const auto v = value();
      if (!v) {
        return result;
      }
      options.rules_path = *v;
    } else if (arg == "--report") {
      const auto v = value();
      if (!v) {
        return result;
      }
      options.report_path = *v;
    } else if (arg == "--lbs") {
      if (!count(options.num_lbs, kMaxLbs)) {
        return result;
      }
    } else if (arg == "--fps-per-lb") {
      if (!count(options.fps_per_lb, kMaxFpsPerLb)) {
        return result;
      }
    } else if (arg == "--queue-size") {
      if (!count(options.queue_size, kMaxQueueSize)) {
        return result;
      }
    } else if (arg == "--batch-size") {
      if (!count(options.batch_size, kMaxBatchSize)) {
        return result;
      }
    } else if (arg == "--sequential") {
      options.sequential = true;
    } else if (arg.starts_with("-")) {
      result.error = "unknown option " + arg;
      return result;
    } else {
      positional.push_back(arg);
    }
  }

  if (positional.size() != 2) {
    result.error = "expected <input.pcap> and <output.pcap>";
    return result;
  }
  options.input_path = positional[0];
  options.output_path = positional[1];
  result.options = options;
  return result;
}

}  // namespace dpi
