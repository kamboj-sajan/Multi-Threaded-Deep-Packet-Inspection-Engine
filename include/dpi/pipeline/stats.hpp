#pragma once

// Statistics are collected per stage and per thread with plain counters:
// each stage object is used by exactly one thread, so there is nothing to
// synchronise while running. RunStats merges them after every thread has
// been joined.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "dpi/common/types.hpp"
#include "dpi/parser/parsed_packet.hpp"

namespace dpi {

struct ReaderStats {
  std::uint64_t packets = 0;            // Complete records handed downstream.
  std::uint64_t bytes = 0;              // Captured bytes of those records.
  std::uint64_t truncated_records = 0;  // Input ended inside a record.
  std::uint64_t corrupt_records = 0;    // Nonsensical record header.
};

struct LbStats {
  std::uint64_t packets = 0;  // Packets received from the reader.
  std::uint64_t malformed = 0;
  std::array<std::uint64_t, kParseStatusCount> malformed_by_reason{};
};

struct AppCounters {
  std::uint64_t flows = 0;
  std::uint64_t packets = 0;
  std::uint64_t bytes = 0;
};

struct FpStats {
  std::uint64_t packets = 0;    // Packets received from the load balancer.
  std::uint64_t bytes = 0;
  std::uint64_t forwarded = 0;
  std::uint64_t dropped = 0;    // By a blocking rule.
  std::uint64_t non_ip = 0;     // Forwarded without flow tracking.
  std::uint64_t flows_created = 0;
  std::uint64_t flows_expired = 0;
  std::uint64_t flows_evicted = 0;
  std::uint64_t flows_blocked = 0;
  std::array<std::uint64_t, kBlockReasonCount> flows_blocked_by_reason{};
  std::array<AppCounters, kAppCount> apps{};
  std::unordered_map<std::string, std::uint64_t> sni_flows;  // SNI -> flow count

  void merge(const FpStats& other);
};

struct WriterStats {
  std::uint64_t packets = 0;
  std::uint64_t bytes = 0;
};

struct SniCount {
  std::string sni;
  std::uint64_t flows = 0;
};

struct RunStats {
  std::size_t num_lbs = 1;
  std::size_t fps_per_lb = 1;
  ReaderStats reader;
  std::vector<LbStats> lbs;
  std::vector<FpStats> fps;  // Index = lb * fps_per_lb + fp.
  WriterStats writer;
  double elapsed_seconds = 0.0;

  // Every input record ends up in exactly one of forwarded, dropped or
  // malformed, so total_packets() == forwarded() + dropped() + malformed().
  std::uint64_t total_packets() const noexcept;
  std::uint64_t malformed() const noexcept;
  std::uint64_t forwarded() const noexcept;
  std::uint64_t dropped() const noexcept;
  std::array<std::uint64_t, kParseStatusCount> malformed_by_reason() const noexcept;
  FpStats merged_fast_path() const;
};

// Highest flow counts first; ties broken by name so output is stable.
std::vector<SniCount> top_snis(const FpStats& stats, std::size_t limit);

}  // namespace dpi
