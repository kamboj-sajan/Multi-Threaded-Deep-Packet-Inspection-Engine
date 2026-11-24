#include <gtest/gtest.h>

#include "dpi/app/cli.hpp"

namespace dpi {
namespace {

TEST(Cli, ParsesPositionalArgumentsAndReport) {
  const auto r = parse_cli({"in.pcap", "out.pcap", "--report", "r.json"});
  ASSERT_TRUE(r.options.has_value()) << r.error;
  EXPECT_EQ(r.options->input_path, "in.pcap");
  EXPECT_EQ(r.options->output_path, "out.pcap");
  EXPECT_EQ(r.options->report_path, "r.json");
}

TEST(Cli, OptionsMayPrecedePositionals) {
  const auto r = parse_cli({"--report", "r.json", "in.pcap", "out.pcap"});
  ASSERT_TRUE(r.options.has_value()) << r.error;
  EXPECT_EQ(r.options->input_path, "in.pcap");
}

TEST(Cli, RejectsBadInvocations) {
  EXPECT_FALSE(parse_cli({}).options.has_value());
  EXPECT_FALSE(parse_cli({"in.pcap"}).options.has_value());
  EXPECT_FALSE(parse_cli({"a", "b", "c"}).options.has_value());
  EXPECT_FALSE(parse_cli({"a", "b", "--report"}).options.has_value());
  const auto unknown = parse_cli({"a", "b", "--bogus"});
  EXPECT_FALSE(unknown.options.has_value());
  EXPECT_NE(unknown.error.find("--bogus"), std::string::npos);
}

TEST(Cli, HelpFlag) {
  EXPECT_TRUE(parse_cli({"--help"}).show_help);
  EXPECT_TRUE(parse_cli({"in", "-h"}).show_help);
}

}  // namespace
}  // namespace dpi
