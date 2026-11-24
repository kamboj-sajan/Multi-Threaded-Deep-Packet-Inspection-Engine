#include "dpi/pipeline/report.hpp"

#include <algorithm>
#include <cstdio>
#include <iomanip>
#include <sstream>
#include <vector>

namespace dpi {
namespace {

struct Throughput {
  double packets_per_second = 0.0;
  double mbps = 0.0;
};

// Throughput counts captured bytes: that is what the engine actually
// processed, even when snaplen cut packets short on the wire.
Throughput throughput(const RunStats& s) {
  if (s.elapsed_seconds <= 0.0) {
    return {};
  }
  return {static_cast<double>(s.total_packets()) / s.elapsed_seconds,
          static_cast<double>(s.reader.bytes) * 8.0 / s.elapsed_seconds / 1e6};
}

std::string fp_label(const RunStats& s, std::size_t index) {
  return std::to_string(index / s.fps_per_lb) + "." + std::to_string(index % s.fps_per_lb);
}

struct AppRow {
  AppId app;
  AppCounters counters;
};

// Applications that saw traffic, busiest first (ties by name for stability).
std::vector<AppRow> active_apps(const FpStats& fp) {
  std::vector<AppRow> rows;
  for (std::size_t i = 0; i < kAppCount; ++i) {
    if (fp.apps[i].flows > 0) {
      rows.push_back({static_cast<AppId>(i), fp.apps[i]});
    }
  }
  std::sort(rows.begin(), rows.end(), [](const AppRow& a, const AppRow& b) {
    if (a.counters.packets != b.counters.packets) {
      return a.counters.packets > b.counters.packets;
    }
    return to_string(a.app) < to_string(b.app);
  });
  return rows;
}

std::string percent(std::uint64_t part, std::uint64_t whole) {
  char buf[16];
  std::snprintf(buf, sizeof buf, "%5.1f%%", whole == 0 ? 0.0 : 100.0 * part / whole);
  return buf;
}

}  // namespace

std::string json_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  for (const char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof buf, "\\u%04x", static_cast<unsigned>(c));
          out += buf;
        } else {
          out += c;
        }
    }
  }
  return out;
}

std::string format_text_report(const RunStats& s) {
  const FpStats fp = s.merged_fast_path();
  const std::uint64_t total = s.total_packets();
  const Throughput tp = throughput(s);
  std::ostringstream o;

  o << "=== DPI engine report ===\n";
  o << "Packets\n";
  o << "  total        " << std::setw(12) << total << '\n';
  o << "  forwarded    " << std::setw(12) << s.forwarded() << "  " << percent(s.forwarded(), total) << '\n';
  o << "  dropped      " << std::setw(12) << s.dropped() << "  " << percent(s.dropped(), total) << '\n';
  o << "  malformed    " << std::setw(12) << s.malformed() << "  " << percent(s.malformed(), total) << '\n';
  const auto reasons = s.malformed_by_reason();
  for (std::size_t i = 1; i < reasons.size(); ++i) {
    if (reasons[i] > 0) {
      o << "    " << std::left << std::setw(22) << to_string(static_cast<ParseStatus>(i)) << std::right
        << std::setw(8) << reasons[i] << '\n';
    }
  }
  if (s.reader.truncated_records + s.reader.corrupt_records > 0) {
    o << "    " << std::left << std::setw(22) << "truncated_record" << std::right << std::setw(8)
      << s.reader.truncated_records + s.reader.corrupt_records << '\n';
  }
  o << "  non-IP (fwd) " << std::setw(12) << fp.non_ip << '\n';

  o << "Flows\n";
  o << "  total        " << std::setw(12) << fp.flows_created << '\n';
  o << "  blocked      " << std::setw(12) << fp.flows_blocked << '\n';
  for (std::size_t i = 1; i < kBlockReasonCount; ++i) {
    if (fp.flows_blocked_by_reason[i] > 0) {
      o << "    by " << std::left << std::setw(20) << to_string(static_cast<BlockReason>(i)) << std::right
        << std::setw(8) << fp.flows_blocked_by_reason[i] << '\n';
    }
  }
  o << "  idle-expired " << std::setw(12) << fp.flows_expired << '\n';
  o << "  evicted      " << std::setw(12) << fp.flows_evicted << '\n';

  o << "Threads (" << s.num_lbs << " LB x " << s.fps_per_lb << " FP)\n";
  o << "  reader       " << std::setw(12) << s.reader.packets << '\n';
  for (std::size_t i = 0; i < s.lbs.size(); ++i) {
    o << "  lb " << std::left << std::setw(9) << i << std::right << std::setw(12) << s.lbs[i].packets
      << "  " << percent(s.lbs[i].packets, s.reader.packets) << '\n';
  }
  std::uint64_t fp_total = 0;
  for (const FpStats& f : s.fps) {
    fp_total += f.packets;
  }
  for (std::size_t i = 0; i < s.fps.size(); ++i) {
    o << "  fp " << std::left << std::setw(9) << fp_label(s, i) << std::right << std::setw(12)
      << s.fps[i].packets << "  " << percent(s.fps[i].packets, fp_total) << '\n';
  }
  o << "  writer       " << std::setw(12) << s.writer.packets << '\n';

  o << "Applications (flows / packets / bytes)\n";
  for (const AppRow& row : active_apps(fp)) {
    o << "  " << std::left << std::setw(12) << to_string(row.app) << std::right << std::setw(8)
      << row.counters.flows << std::setw(12) << row.counters.packets << std::setw(14)
      << row.counters.bytes << '\n';
  }

  o << "Top SNIs / HTTP hosts (flows)\n";
  const auto snis = top_snis(fp, kTopSniCount);
  if (snis.empty()) {
    o << "  (none)\n";
  }
  for (std::size_t i = 0; i < snis.size(); ++i) {
    o << "  " << std::setw(2) << i + 1 << ". " << std::left << std::setw(40) << snis[i].sni
      << std::right << std::setw(6) << snis[i].flows << '\n';
  }

  o << std::fixed << std::setprecision(3);
  o << "Performance\n";
  o << "  elapsed      " << std::setw(12) << s.elapsed_seconds << " s\n";
  o << std::setprecision(0);
  o << "  rate         " << std::setw(12) << tp.packets_per_second << " packets/s\n";
  o << std::setprecision(1);
  o << "  throughput   " << std::setw(12) << tp.mbps << " Mbps\n";
  return o.str();
}

std::string format_json_report(const RunStats& s) {
  const FpStats fp = s.merged_fast_path();
  const Throughput tp = throughput(s);
  std::ostringstream o;
  o << std::setprecision(6);

  o << "{\n";
  o << "  \"packets\": {\"total\": " << s.total_packets() << ", \"forwarded\": " << s.forwarded()
    << ", \"dropped\": " << s.dropped() << ", \"malformed\": " << s.malformed()
    << ", \"non_ip\": " << fp.non_ip << "},\n";

  o << "  \"malformed_by_reason\": {";
  const auto reasons = s.malformed_by_reason();
  for (std::size_t i = 1; i < reasons.size(); ++i) {
    o << '"' << to_string(static_cast<ParseStatus>(i)) << "\": " << reasons[i] << ", ";
  }
  o << "\"truncated_record\": " << s.reader.truncated_records + s.reader.corrupt_records << "},\n";

  o << "  \"flows\": {\"total\": " << fp.flows_created << ", \"blocked\": " << fp.flows_blocked
    << ", \"idle_expired\": " << fp.flows_expired << ", \"evicted\": " << fp.flows_evicted << "},\n";
  o << "  \"blocked_flows_by_rule\": {";
  for (std::size_t i = 1; i < kBlockReasonCount; ++i) {
    o << (i > 1 ? ", " : "") << '"' << to_string(static_cast<BlockReason>(i)) << "\": "
      << fp.flows_blocked_by_reason[i];
  }
  o << "},\n";

  o << "  \"threads\": {\n";
  o << "    \"num_lbs\": " << s.num_lbs << ", \"fps_per_lb\": " << s.fps_per_lb << ",\n";
  o << "    \"reader\": {\"packets\": " << s.reader.packets << "},\n";
  o << "    \"lb\": [";
  for (std::size_t i = 0; i < s.lbs.size(); ++i) {
    o << (i ? ", " : "") << "{\"id\": " << i << ", \"packets\": " << s.lbs[i].packets
      << ", \"malformed\": " << s.lbs[i].malformed << '}';
  }
  o << "],\n    \"fp\": [";
  for (std::size_t i = 0; i < s.fps.size(); ++i) {
    o << (i ? ", " : "") << "{\"id\": \"" << fp_label(s, i) << "\", \"packets\": " << s.fps[i].packets
      << ", \"forwarded\": " << s.fps[i].forwarded << ", \"dropped\": " << s.fps[i].dropped
      << ", \"flows\": " << s.fps[i].flows_created << '}';
  }
  o << "],\n    \"writer\": {\"packets\": " << s.writer.packets << "}\n  },\n";

  o << "  \"apps\": [";
  const auto apps = active_apps(fp);
  for (std::size_t i = 0; i < apps.size(); ++i) {
    o << (i ? ", " : "") << "{\"app\": \"" << to_string(apps[i].app) << "\", \"flows\": "
      << apps[i].counters.flows << ", \"packets\": " << apps[i].counters.packets
      << ", \"bytes\": " << apps[i].counters.bytes << '}';
  }
  o << "],\n";

  o << "  \"top_snis\": [";
  const auto snis = top_snis(fp, kTopSniCount);
  for (std::size_t i = 0; i < snis.size(); ++i) {
    o << (i ? ", " : "") << "{\"sni\": \"" << json_escape(snis[i].sni) << "\", \"flows\": "
      << snis[i].flows << '}';
  }
  o << "],\n";

  o << "  \"performance\": {\"elapsed_seconds\": " << s.elapsed_seconds
    << ", \"packets_per_second\": " << tp.packets_per_second << ", \"mbps\": " << tp.mbps << "}\n";
  o << "}\n";
  return o.str();
}

}  // namespace dpi
