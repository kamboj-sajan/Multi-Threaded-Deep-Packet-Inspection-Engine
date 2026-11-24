#include "dpi/pipeline/stats.hpp"

#include <algorithm>

namespace dpi {

void FpStats::merge(const FpStats& other) {
  packets += other.packets;
  bytes += other.bytes;
  forwarded += other.forwarded;
  dropped += other.dropped;
  non_ip += other.non_ip;
  flows_created += other.flows_created;
  flows_expired += other.flows_expired;
  flows_evicted += other.flows_evicted;
  flows_blocked += other.flows_blocked;
  for (std::size_t i = 0; i < flows_blocked_by_reason.size(); ++i) {
    flows_blocked_by_reason[i] += other.flows_blocked_by_reason[i];
  }
  for (std::size_t i = 0; i < apps.size(); ++i) {
    apps[i].flows += other.apps[i].flows;
    apps[i].packets += other.apps[i].packets;
    apps[i].bytes += other.apps[i].bytes;
  }
  for (const auto& [sni, flows] : other.sni_flows) {
    sni_flows[sni] += flows;
  }
}

std::uint64_t RunStats::total_packets() const noexcept {
  return reader.packets + reader.truncated_records + reader.corrupt_records;
}

std::uint64_t RunStats::malformed() const noexcept {
  std::uint64_t n = reader.truncated_records + reader.corrupt_records;
  for (const LbStats& lb : lbs) {
    n += lb.malformed;
  }
  return n;
}

std::uint64_t RunStats::forwarded() const noexcept {
  std::uint64_t n = 0;
  for (const FpStats& fp : fps) {
    n += fp.forwarded;
  }
  return n;
}

std::uint64_t RunStats::dropped() const noexcept {
  std::uint64_t n = 0;
  for (const FpStats& fp : fps) {
    n += fp.dropped;
  }
  return n;
}

std::array<std::uint64_t, kParseStatusCount> RunStats::malformed_by_reason() const noexcept {
  std::array<std::uint64_t, kParseStatusCount> total{};
  for (const LbStats& lb : lbs) {
    for (std::size_t i = 0; i < total.size(); ++i) {
      total[i] += lb.malformed_by_reason[i];
    }
  }
  return total;
}

FpStats RunStats::merged_fast_path() const {
  FpStats merged;
  for (const FpStats& fp : fps) {
    merged.merge(fp);
  }
  return merged;
}

std::vector<SniCount> top_snis(const FpStats& stats, std::size_t limit) {
  std::vector<SniCount> all;
  all.reserve(stats.sni_flows.size());
  for (const auto& [sni, flows] : stats.sni_flows) {
    all.push_back({sni, flows});
  }
  std::sort(all.begin(), all.end(), [](const SniCount& a, const SniCount& b) {
    return a.flows != b.flows ? a.flows > b.flows : a.sni < b.sni;
  });
  if (all.size() > limit) {
    all.resize(limit);
  }
  return all;
}

}  // namespace dpi
