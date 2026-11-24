#include "dpi/app/cli.hpp"

namespace dpi {

std::string usage_text() {
  return "usage: dpi_engine <input.pcap> <output.pcap> [options]\n"
         "\n"
         "Reads an Ethernet PCAP, inspects every flow, writes the forwarded\n"
         "packets to <output.pcap> and prints a statistics report.\n"
         "\n"
         "options:\n"
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
    if (arg == "--report") {
      const auto v = value();
      if (!v) {
        return result;
      }
      options.report_path = *v;
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
