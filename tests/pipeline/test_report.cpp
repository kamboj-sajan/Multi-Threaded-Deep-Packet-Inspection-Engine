#include <gtest/gtest.h>

#include "dpi/pipeline/report.hpp"

namespace dpi {
namespace {

RunStats sample_stats() {
  RunStats s;
  s.num_lbs = 1;
  s.fps_per_lb = 2;
  s.reader.packets = 10;
  s.reader.bytes = 1000;
  s.reader.truncated_records = 1;
  s.lbs.resize(1);
  s.lbs[0].packets = 10;
  s.lbs[0].malformed = 2;
  s.lbs[0].malformed_by_reason[static_cast<std::size_t>(ParseStatus::TruncatedTcp)] = 2;
  s.fps.resize(2);
  s.fps[0].packets = 5;
  s.fps[0].forwarded = 4;
  s.fps[0].dropped = 1;
  s.fps[0].flows_created = 2;
  s.fps[0].apps[static_cast<std::size_t>(AppId::YouTube)] = {1, 3, 300};
  s.fps[0].sni_flows["www.youtube.com"] = 1;
  s.fps[1].packets = 3;
  s.fps[1].forwarded = 3;
  s.fps[1].flows_created = 1;
  s.fps[1].apps[static_cast<std::size_t>(AppId::DNS)] = {1, 2, 200};
  s.fps[1].sni_flows["evil\"quote.com"] = 1;
  s.writer.packets = 7;
  s.elapsed_seconds = 0.5;
  return s;
}

TEST(Report, TotalsAddUp) {
  const RunStats s = sample_stats();
  EXPECT_EQ(s.total_packets(), 11u);
  EXPECT_EQ(s.forwarded() + s.dropped() + s.malformed(), 11u);
}

TEST(Report, TextReportShowsKeySections) {
  const std::string text = format_text_report(sample_stats());
  for (const char* needle : {"forwarded", "malformed", "truncated_tcp", "fp 0.1", "YouTube",
                             "www.youtube.com", "packets/s", "Mbps"}) {
    EXPECT_NE(text.find(needle), std::string::npos) << "missing: " << needle;
  }
}

TEST(Report, JsonReportContainsEscapedValues) {
  const std::string json = format_json_report(sample_stats());
  EXPECT_NE(json.find("\"total\": 11"), std::string::npos);
  EXPECT_NE(json.find("\"forwarded\": 7"), std::string::npos);
  EXPECT_NE(json.find("\"truncated_tcp\": 2"), std::string::npos);
  EXPECT_NE(json.find("\"truncated_record\": 1"), std::string::npos);
  EXPECT_NE(json.find("{\"id\": \"0.1\", \"packets\": 3"), std::string::npos);
  EXPECT_NE(json.find("evil\\\"quote.com"), std::string::npos);
  EXPECT_NE(json.find("\"packets_per_second\": 22"), std::string::npos);  // 11 / 0.5
}

TEST(Report, JsonEscapeHandlesControlCharacters) {
  EXPECT_EQ(json_escape("a\"b\\c\n\x01"), "a\\\"b\\\\c\\n\\u0001");
}

}  // namespace
}  // namespace dpi
