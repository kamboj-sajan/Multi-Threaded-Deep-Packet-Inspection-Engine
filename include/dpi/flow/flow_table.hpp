#pragma once

#include <cstddef>
#include <cstdint>
#include <list>
#include <unordered_map>

#include "dpi/flow/five_tuple.hpp"
#include "dpi/flow/flow_entry.hpp"

namespace dpi {

struct FlowTableConfig {
  // A flow idle for longer than this (in capture time) is over; its next
  // packet starts a new flow.
  std::uint64_t idle_timeout_ns = 120ULL * 1'000'000'000ULL;
  // Upper bound on tracked flows per table. When reached, the least
  // recently used flow is evicted to make room.
  std::size_t max_flows = 1u << 20;
};

struct FlowTableStats {
  std::uint64_t created = 0;
  std::uint64_t expired_idle = 0;       // Ended by idle timeout.
  std::uint64_t evicted_capacity = 0;   // Forced out because the table was full.
};

// Flow table owned by exactly one fast-path thread, so it has no locks.
//
// Flows live in a list kept in least-recently-used order (front = most
// recent), indexed by a hash map. This makes lookup, touch, insertion and
// capacity eviction O(1), and idle sweeps O(number of expired flows)
// because they walk from the back and stop at the first live flow.
//
// All time comes from packet timestamps, never the wall clock, so results
// are reproducible however fast the capture is replayed.
class FlowTable {
 public:
  explicit FlowTable(FlowTableConfig config = {});

  struct LookupResult {
    FlowEntry* entry;  // Valid until the next mutating call.
    bool created;
  };

  // Returns the flow for `key`, creating it if it does not exist or if the
  // existing one has been idle longer than the timeout at `now_ns`. That
  // per-flow check is what makes expiry deterministic: it depends only on
  // this flow's own packets, not on when sweeps run.
  LookupResult find_or_create(const FiveTuple& key, Direction direction, std::uint8_t tcp_flags,
                              std::uint64_t now_ns);

  FlowEntry* find(const FiveTuple& key) noexcept;

  // Replaces an existing flow with a fresh one (e.g. a new SYN reusing the
  // 5-tuple of a closed connection). Counts as a new flow.
  FlowEntry& restart(FlowEntry& entry, Direction direction, std::uint8_t tcp_flags,
                     std::uint64_t now_ns);

  // Drops flows idle at `now_ns`. Only reclaims memory: find_or_create
  // already treats idle flows as gone, so calling this never changes
  // results.
  std::size_t expire_idle(std::uint64_t now_ns);

  std::size_t size() const noexcept { return index_.size(); }
  const FlowTableStats& stats() const noexcept { return stats_; }
  const FlowTableConfig& config() const noexcept { return config_; }

  template <typename Fn>
  void for_each(Fn&& fn) const {
    for (const FlowEntry& e : lru_) {
      fn(e);
    }
  }

 private:
  using List = std::list<FlowEntry>;

  bool is_idle(const FlowEntry& e, std::uint64_t now_ns) const noexcept;
  void reset_entry(FlowEntry& e, Direction direction, std::uint8_t tcp_flags,
                   std::uint64_t now_ns) noexcept;
  void touch(List::iterator it) noexcept;

  FlowTableConfig config_;
  List lru_;
  std::unordered_map<FiveTuple, List::iterator, FiveTupleHash> index_;
  FlowTableStats stats_;
};

}  // namespace dpi
