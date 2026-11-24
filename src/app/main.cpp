// dpi_engine: command-line entry point. All logic lives in the libraries;
// this file only wires options to the engine and handles errors.

#include <exception>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "dpi/app/cli.hpp"
#include "dpi/pcap_io/pcap_reader.hpp"
#include "dpi/pcap_io/pcap_writer.hpp"
#include "dpi/pipeline/engine.hpp"
#include "dpi/pipeline/report.hpp"
#include "dpi/rules/rule_set.hpp"

namespace {

constexpr int kExitOk = 0;
constexpr int kExitRuntimeError = 1;
constexpr int kExitUsage = 2;

int run(const dpi::CliOptions& options) {
  // Load rules first so a typo in the rules file fails before any output
  // file is created.
  std::shared_ptr<const dpi::RuleSet> rules;
  if (options.rules_path) {
    rules = dpi::RuleSet::load_file(*options.rules_path);
    std::cout << "Loaded " << rules->size() << " rules from " << *options.rules_path << "\n";
  }
  dpi::PcapReader reader = dpi::PcapReader::open_file(options.input_path);
  // Mirror the input's format so timestamps keep their precision.
  dpi::PcapWriter writer = dpi::PcapWriter::create_file(
      options.output_path, {.snaplen = reader.info().snaplen,
                            .linktype = reader.info().linktype,
                            .precision = reader.info().precision});

  dpi::EngineConfig config;
  config.num_lbs = options.num_lbs;
  config.fps_per_lb = options.fps_per_lb;
  config.queue_capacity = options.queue_size;
  config.batch_size = options.batch_size;
  config.fast_path.rules = rules;
  const dpi::RunStats stats = options.sequential ? dpi::run_sequential(reader, writer, config)
                                                 : dpi::run_pipeline(reader, writer, config);

  std::cout << dpi::format_text_report(stats);
  if (options.report_path) {
    std::ofstream report(*options.report_path);
    report << dpi::format_json_report(stats);
    if (!report) {
      std::cerr << "error: cannot write report to " << *options.report_path << '\n';
      return kExitRuntimeError;
    }
  }
  return kExitOk;
}

}  // namespace

int main(int argc, char** argv) {
  const std::vector<std::string> args(argv + 1, argv + argc);
  const dpi::CliParseResult parsed = dpi::parse_cli(args);
  if (parsed.show_help) {
    std::cout << dpi::usage_text();
    return kExitOk;
  }
  if (!parsed.options) {
    std::cerr << "error: " << parsed.error << "\n\n" << dpi::usage_text();
    return kExitUsage;
  }

  try {
    return run(*parsed.options);
  } catch (const std::exception& e) {
    std::cerr << "error: " << e.what() << '\n';
    return kExitRuntimeError;
  }
}
