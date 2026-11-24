#include "dpi/flow/flow_table.hpp"

#include <algorithm>

namespace dpi {

FlowTable::FlowTable(FlowTableConfig config) : config_(config) {
  config_.max_flows = std::max<std::size_t>(config_.max_flows, 1);
  // Reserve a modest amount up front; rehashing a huge table mid-run would
  // cause a latency spike on this worker.
  index_.reserve(std::min<std::size_t>(config_.max_flows, 1u << 16));
}

bool FlowTable::is_idle(const FlowEntry& e, std::uint64_t now_ns) const noexcept {
  // Captures can contain slightly out-of-order timestamps; never treat
  // "now" earlier than last_seen as a long idle period.
  return now_ns > e.last_seen_ns && now_ns - e.last_seen_ns > config_.idle_timeout_ns;
}

void FlowTable::reset_entry(FlowEntry& e, Direction direction, std::uint8_t tcp_flags,
                            std::uint64_t now_ns) noexcept {
  const FiveTuple key = e.key;
  e = FlowEntry{};
  e.key = key;
  e.client_direction = initial_client_direction(direction, key.protocol, tcp_flags);
  e.first_seen_ns = now_ns;
  e.last_seen_ns = now_ns;
  ++stats_.created;
}

void FlowTable::touch(List::iterator it) noexcept {
  // splice relinks the node without moving the FlowEntry, so pointers to
  // it stay valid.
  lru_.splice(lru_.begin(), lru_, it);
}

FlowTable::LookupResult FlowTable::find_or_create(const FiveTuple& key, Direction direction,
                                                  std::uint8_t tcp_flags, std::uint64_t now_ns) {
  if (auto found = index_.find(key); found != index_.end()) {
    FlowEntry& entry = *found->second;
    touch(found->second);
    if (is_idle(entry, now_ns)) {
      ++stats_.expired_idle;
      reset_entry(entry, direction, tcp_flags, now_ns);
      return {&entry, true};
    }
    return {&entry, false};
  }

  if (index_.size() >= config_.max_flows) {
    // Reclaim idle flows first; only if none are idle evict the LRU one.
    expire_idle(now_ns);
    if (index_.size() >= config_.max_flows) {
      index_.erase(lru_.back().key);
      lru_.pop_back();
      ++stats_.evicted_capacity;
    }
  }

  lru_.emplace_front();
  FlowEntry& entry = lru_.front();
  entry.key = key;
  reset_entry(entry, direction, tcp_flags, now_ns);
  index_.emplace(key, lru_.begin());
  return {&entry, true};
}

FlowEntry* FlowTable::find(const FiveTuple& key) noexcept {
  const auto found = index_.find(key);
  return found == index_.end() ? nullptr : &*found->second;
}

FlowEntry& FlowTable::restart(FlowEntry& entry, Direction direction, std::uint8_t tcp_flags,
                              std::uint64_t now_ns) {
  reset_entry(entry, direction, tcp_flags, now_ns);
  return entry;
}

std::size_t FlowTable::expire_idle(std::uint64_t now_ns) {
  std::size_t removed = 0;
  // The list is in recency order, so idle flows are all at the back.
  while (!lru_.empty() && is_idle(lru_.back(), now_ns)) {
    index_.erase(lru_.back().key);
    lru_.pop_back();
    ++stats_.expired_idle;
    ++removed;
  }
  return removed;
}

}  // namespace dpi
