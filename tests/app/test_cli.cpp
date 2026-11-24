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

TEST(Cli, ParsesRulesPath) {
  const auto r = parse_cli({"in", "out", "--rules", "rules/example_rules.txt"});
  ASSERT_TRUE(r.options.has_value()) << r.error;
  EXPECT_EQ(r.options->rules_path, "rules/example_rules.txt");
  EXPECT_FALSE(parse_cli({"in", "out", "--rules"}).options.has_value());
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

TEST(Cli, DefaultsToTwoByTwoPipeline) {
  const auto r = parse_cli({"in", "out"});
  ASSERT_TRUE(r.options.has_value());
  EXPECT_EQ(r.options->num_lbs, 2u);
  EXPECT_EQ(r.options->fps_per_lb, 2u);
  EXPECT_EQ(r.options->queue_size, 4096u);
  EXPECT_FALSE(r.options->sequential);
}

TEST(Cli, ParsesThreadLayout) {
  const auto r = parse_cli({"in", "out", "--lbs", "4", "--fps-per-lb", "3", "--queue-size", "64", "--sequential"});
  ASSERT_TRUE(r.options.has_value()) << r.error;
  EXPECT_EQ(r.options->num_lbs, 4u);
  EXPECT_EQ(r.options->fps_per_lb, 3u);
  EXPECT_EQ(r.options->queue_size, 64u);
  EXPECT_TRUE(r.options->sequential);
}

TEST(Cli, RejectsBadCounts) {
  for (const char* bad : {"0", "-1", "3x", "", "65", "99999999999999999999"}) {
    const auto r = parse_cli({"in", "out", "--lbs", bad});
    EXPECT_FALSE(r.options.has_value()) << "accepted --lbs '" << bad << "'";
    EXPECT_NE(r.error.find("--lbs"), std::string::npos);
  }
  EXPECT_FALSE(parse_cli({"in", "out", "--queue-size", "0"}).options.has_value());
  EXPECT_FALSE(parse_cli({"in", "out", "--fps-per-lb"}).options.has_value());
}

TEST(Cli, HelpFlag) {
  EXPECT_TRUE(parse_cli({"--help"}).show_help);
  EXPECT_TRUE(parse_cli({"in", "-h"}).show_help);
}

}  // namespace
}  // namespace dpi
