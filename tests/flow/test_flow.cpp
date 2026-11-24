#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <vector>
#include <random>
#include <unordered_set>

#include "dpi/flow/five_tuple.hpp"
#include "dpi/flow/flow_table.hpp"
#include "dpi/flow/tcp_tracker.hpp"
#include "dpi/parser/parsed_packet.hpp"
#include "packet_builder.hpp"

namespace dpi {
namespace {

using test::ip;

constexpr std::uint64_t kSec = 1'000'000'000ULL;

PacketTuple tuple(std::uint32_t sip, std::uint16_t sport, std::uint32_t dip, std::uint16_t dport,
                  std::uint8_t proto = ipproto::kTcp) {
  return PacketTuple{sip, dip, sport, dport, proto};
}

PacketTuple reversed(const PacketTuple& t) {
  return PacketTuple{t.dst_ip, t.src_ip, t.dst_port, t.src_port, t.protocol};
}

FiveTuple key_of(std::uint32_t n) {
  return normalize(tuple(ip(10, 0, 0, 1), static_cast<std::uint16_t>(1024 + n), ip(10, 0, 0, 2), 80)).key;
}

// --- FiveTuple / hashing --------------------------------------------------

TEST(FiveTuple, BothDirectionsNormaliseToTheSameKey) {
  const PacketTuple fwd = tuple(ip(192, 168, 1, 10), 51000, ip(142, 250, 1, 1), 443);
  const NormalizedTuple a = normalize(fwd);
  const NormalizedTuple b = normalize(reversed(fwd));
  EXPECT_EQ(a.key, b.key);
  EXPECT_NE(a.direction, b.direction);
  EXPECT_EQ(flow_hash(a.key), flow_hash(b.key));
}

TEST(FiveTuple, SmallerEndpointComesFirst) {
  const NormalizedTuple n = normalize(tuple(ip(10, 0, 0, 9), 1000, ip(10, 0, 0, 1), 2000));
  EXPECT_EQ(n.key.ip_lo, ip(10, 0, 0, 1));
  EXPECT_EQ(n.key.port_lo, 2000);
  EXPECT_EQ(n.key.ip_hi, ip(10, 0, 0, 9));
  EXPECT_EQ(n.key.port_hi, 1000);
  EXPECT_EQ(n.direction, Direction::HiToLo);
}

TEST(FiveTuple, SameHostPairOrdersByPort) {
  // Same IPs both ways: the port decides, so both directions still agree.
  const PacketTuple t = tuple(ip(10, 0, 0, 1), 9000, ip(10, 0, 0, 1), 80);
  EXPECT_EQ(normalize(t).key, normalize(reversed(t)).key);
  EXPECT_EQ(normalize(t).key.port_lo, 80);
}

TEST(FiveTuple, DistinguishesProtocolAndPorts) {
  const PacketTuple base = tuple(ip(1, 2, 3, 4), 1111, ip(5, 6, 7, 8), 53, ipproto::kTcp);
  PacketTuple udp = base;
  udp.protocol = ipproto::kUdp;
  PacketTuple other_port = base;
  other_port.src_port = 1112;
  EXPECT_NE(normalize(base).key, normalize(udp).key);
  EXPECT_NE(normalize(base).key, normalize(other_port).key);
  EXPECT_NE(flow_hash(normalize(base).key), flow_hash(normalize(udp).key));
}

TEST(FiveTuple, HashIsPinnedAcrossPlatforms) {
  // The hash decides which thread handles a flow. Pinning one value proves
  // it does not depend on endianness, padding or the standard library.
  const FiveTuple key = normalize(tuple(ip(192, 168, 0, 1), 1234, ip(8, 8, 8, 8), 53, ipproto::kUdp)).key;
  // Expected value computed independently with a Python FNV-1a + fmix64.
  EXPECT_EQ(flow_hash(key), 0xadaedcbe13c55be3ULL);
}

TEST(FiveTuple, HashSpreadsEvenlyOverWorkers) {
  // Mirrors the pipeline's routing: LB = h % N, FP = (h / N) % K.
  constexpr std::size_t kLbs = 4;
  constexpr std::size_t kFps = 4;
  constexpr int kFlows = 64000;
  std::array<int, kLbs * kFps> buckets{};
  std::mt19937 rng(7);
  for (int i = 0; i < kFlows; ++i) {
    const auto t = tuple(ip(10, 0, static_cast<std::uint8_t>(rng() % 4), static_cast<std::uint8_t>(rng())),
                         static_cast<std::uint16_t>(32768 + rng() % 28000), ip(93, 184, 216, 34), 443);
    const std::uint64_t h = flow_hash(normalize(t).key);
    ++buckets[(h % kLbs) * kFps + (h / kLbs) % kFps];
  }
  const double expected = static_cast<double>(kFlows) / buckets.size();
  for (const int count : buckets) {
    EXPECT_NEAR(count, expected, expected * 0.10);  // within 10% of perfect
  }
}

TEST(FiveTuple, FormatsReadably) {
  EXPECT_EQ(ipv4_to_string(ip(192, 168, 1, 50)), "192.168.1.50");
  EXPECT_EQ(to_string(normalize(tuple(ip(10, 0, 0, 2), 80, ip(10, 0, 0, 1), 5000)).key),
            "10.0.0.1:5000 <-> 10.0.0.2:80 proto 6");
}

// --- TcpTracker -----------------------------------------------------------

TEST(TcpTracker, FullHandshakeAndGracefulClose) {
  TcpTracker t;
  t.on_packet(tcpflag::kSyn, true);
  EXPECT_EQ(t.state(), TcpState::SynSent);
  t.on_packet(tcpflag::kSyn | tcpflag::kAck, false);
  EXPECT_EQ(t.state(), TcpState::SynReceived);
  t.on_packet(tcpflag::kAck, true);
  EXPECT_EQ(t.state(), TcpState::Established);
  t.on_packet(tcpflag::kPsh | tcpflag::kAck, true);
  EXPECT_EQ(t.state(), TcpState::Established);
  t.on_packet(tcpflag::kFin | tcpflag::kAck, true);
  EXPECT_EQ(t.state(), TcpState::Closing);
  t.on_packet(tcpflag::kFin | tcpflag::kAck, false);
  EXPECT_EQ(t.state(), TcpState::Closed);
  EXPECT_TRUE(t.is_terminal());
}

TEST(TcpTracker, RstResetsFromAnyState) {
  TcpTracker t;
  t.on_packet(tcpflag::kSyn, true);
  t.on_packet(tcpflag::kRst | tcpflag::kAck, false);
  EXPECT_EQ(t.state(), TcpState::Reset);
  t.on_packet(tcpflag::kAck, true);  // terminal: ignored
  EXPECT_EQ(t.state(), TcpState::Reset);
}

TEST(TcpTracker, JoinsConnectionsMidStream) {
  TcpTracker t;
  t.on_packet(tcpflag::kAck | tcpflag::kPsh, true);
  EXPECT_EQ(t.state(), TcpState::Established);
}

TEST(TcpTracker, SynAckFirstMeansWeMissedTheSyn) {
  TcpTracker t;
  t.on_packet(tcpflag::kSyn | tcpflag::kAck, false);
  EXPECT_EQ(t.state(), TcpState::SynReceived);
  t.on_packet(tcpflag::kAck, true);
  EXPECT_EQ(t.state(), TcpState::Established);
}

TEST(TcpTracker, RetransmittedFinFromSameSideDoesNotClose) {
  TcpTracker t;
  t.on_packet(tcpflag::kAck, true);
  t.on_packet(tcpflag::kFin | tcpflag::kAck, true);
  t.on_packet(tcpflag::kFin | tcpflag::kAck, true);
  EXPECT_EQ(t.state(), TcpState::Closing);
}

TEST(FlowEntry, LeadingSynAckIdentifiesTheServer) {
  EXPECT_EQ(initial_client_direction(Direction::LoToHi, ipproto::kTcp, tcpflag::kSyn), Direction::LoToHi);
  EXPECT_EQ(initial_client_direction(Direction::LoToHi, ipproto::kTcp, tcpflag::kSyn | tcpflag::kAck),
            Direction::HiToLo);
  EXPECT_EQ(initial_client_direction(Direction::HiToLo, ipproto::kUdp, 0), Direction::HiToLo);
}

TEST(FlowEntry, AccountsPerDirection) {
  FlowEntry e;
  e.client_direction = Direction::HiToLo;
  e.account(Direction::HiToLo, 100, 5);
  e.account(Direction::HiToLo, 50, 6);
  e.account(Direction::LoToHi, 1500, 7);
  EXPECT_EQ(e.to_server.packets, 2u);
  EXPECT_EQ(e.to_server.bytes, 150u);
  EXPECT_EQ(e.to_client.packets, 1u);
  EXPECT_EQ(e.to_client.bytes, 1500u);
  EXPECT_EQ(e.total_packets(), 3u);
  EXPECT_EQ(e.last_seen_ns, 7u);
}

// --- FlowTable ------------------------------------------------------------

TEST(FlowTable, CreatesOnceAndFindsFromBothDirections) {
  FlowTable table;
  const PacketTuple fwd = tuple(ip(10, 0, 0, 1), 40000, ip(10, 0, 0, 2), 443);
  const NormalizedTuple a = normalize(fwd);
  const NormalizedTuple b = normalize(reversed(fwd));

  const auto first = table.find_or_create(a.key, a.direction, tcpflag::kSyn, 1 * kSec);
  EXPECT_TRUE(first.created);
  EXPECT_EQ(first.entry->client_direction, a.direction);
  EXPECT_EQ(first.entry->first_seen_ns, 1 * kSec);

  const auto second = table.find_or_create(b.key, b.direction, tcpflag::kSyn | tcpflag::kAck, 2 * kSec);
  EXPECT_FALSE(second.created);
  EXPECT_EQ(second.entry, first.entry);
  EXPECT_EQ(table.size(), 1u);
  EXPECT_EQ(table.stats().created, 1u);
  EXPECT_EQ(table.find(a.key), first.entry);
}

TEST(FlowTable, IdleFlowIsReplacedOnNextPacket) {
  FlowTable table({.idle_timeout_ns = 30 * kSec, .max_flows = 100});
  const FiveTuple key = key_of(1);
  FlowEntry* e = table.find_or_create(key, Direction::LoToHi, 0, 0).entry;
  e->account(Direction::LoToHi, 100, 0);
  e->app = AppId::YouTube;

  // Exactly at the timeout: still the same flow.
  auto r = table.find_or_create(key, Direction::LoToHi, 0, 30 * kSec);
  EXPECT_FALSE(r.created);
  r.entry->last_seen_ns = 30 * kSec;

  // Past the timeout (measured from the last packet): a fresh flow.
  r = table.find_or_create(key, Direction::HiToLo, 0, 60 * kSec + 1);
  EXPECT_TRUE(r.created);
  EXPECT_EQ(r.entry->app, AppId::Unknown);
  EXPECT_EQ(r.entry->total_packets(), 0u);
  EXPECT_EQ(r.entry->client_direction, Direction::HiToLo);
  EXPECT_EQ(table.stats().created, 2u);
  EXPECT_EQ(table.stats().expired_idle, 1u);
  EXPECT_EQ(table.size(), 1u);
}

TEST(FlowTable, ExpireIdleRemovesOnlyIdleFlows) {
  FlowTable table({.idle_timeout_ns = 10 * kSec, .max_flows = 100});
  for (std::uint32_t i = 0; i < 5; ++i) {
    table.find_or_create(key_of(i), Direction::LoToHi, 0, i * kSec);
  }
  // Flow 0 is old but gets touched again at t=9s, so it must survive.
  table.find_or_create(key_of(0), Direction::LoToHi, 0, 9 * kSec).entry->last_seen_ns = 9 * kSec;

  // At t=12.5s flows 1 and 2 (last seen at 1s and 2s) have been idle > 10s.
  EXPECT_EQ(table.expire_idle(12 * kSec + kSec / 2), 2u);
  EXPECT_EQ(table.size(), 3u);
  EXPECT_NE(table.find(key_of(0)), nullptr);
  EXPECT_EQ(table.find(key_of(1)), nullptr);
  EXPECT_EQ(table.find(key_of(2)), nullptr);
  EXPECT_NE(table.find(key_of(3)), nullptr);
  EXPECT_EQ(table.stats().expired_idle, 2u);
}

TEST(FlowTable, FullTableEvictsLeastRecentlyUsed) {
  FlowTable table({.idle_timeout_ns = 1000 * kSec, .max_flows = 3});
  table.find_or_create(key_of(0), Direction::LoToHi, 0, 1);
  table.find_or_create(key_of(1), Direction::LoToHi, 0, 2);
  table.find_or_create(key_of(2), Direction::LoToHi, 0, 3);
  table.find_or_create(key_of(0), Direction::LoToHi, 0, 4);  // touch flow 0

  table.find_or_create(key_of(3), Direction::LoToHi, 0, 5);
  EXPECT_EQ(table.size(), 3u);
  EXPECT_EQ(table.find(key_of(1)), nullptr);  // least recently used
  EXPECT_NE(table.find(key_of(0)), nullptr);
  EXPECT_EQ(table.stats().evicted_capacity, 1u);
}

TEST(FlowTable, FullTablePrefersExpiringIdleFlows) {
  FlowTable table({.idle_timeout_ns = 10 * kSec, .max_flows = 2});
  table.find_or_create(key_of(0), Direction::LoToHi, 0, 0);
  table.find_or_create(key_of(1), Direction::LoToHi, 0, 0);
  table.find_or_create(key_of(2), Direction::LoToHi, 0, 20 * kSec);
  EXPECT_EQ(table.stats().evicted_capacity, 0u);
  EXPECT_EQ(table.stats().expired_idle, 2u);
  EXPECT_EQ(table.size(), 1u);
}

TEST(FlowTable, BackwardsTimestampsNeverExpireAFlow) {
  FlowTable table({.idle_timeout_ns = 1 * kSec, .max_flows = 10});
  table.find_or_create(key_of(0), Direction::LoToHi, 0, 100 * kSec);
  EXPECT_FALSE(table.find_or_create(key_of(0), Direction::LoToHi, 0, 5 * kSec).created);
  EXPECT_EQ(table.expire_idle(5 * kSec), 0u);
}

TEST(FlowTable, RestartStartsAFreshFlowForReusedTuple) {
  FlowTable table;
  FlowEntry* e = table.find_or_create(key_of(0), Direction::LoToHi, tcpflag::kSyn, 0).entry;
  e->tcp.on_packet(tcpflag::kRst, true);
  e->verdict = Verdict::Drop;
  FlowEntry& fresh = table.restart(*e, Direction::HiToLo, tcpflag::kSyn, 5);
  EXPECT_EQ(&fresh, e);
  EXPECT_EQ(fresh.verdict, Verdict::Forward);
  EXPECT_EQ(fresh.tcp.state(), TcpState::None);
  EXPECT_EQ(fresh.client_direction, Direction::HiToLo);
  EXPECT_EQ(table.stats().created, 2u);
}

TEST(FlowTable, EntryPointersSurviveOtherInsertions) {
  FlowTable table({.idle_timeout_ns = 1000 * kSec, .max_flows = 10000});
  FlowEntry* first = table.find_or_create(key_of(0), Direction::LoToHi, 0, 0).entry;
  for (std::uint32_t i = 1; i < 5000; ++i) {
    table.find_or_create(key_of(i), Direction::LoToHi, 0, i);  // forces rehashes
  }
  EXPECT_EQ(table.find(key_of(0)), first);
  std::size_t visited = 0;
  table.for_each([&](const FlowEntry&) { ++visited; });
  EXPECT_EQ(visited, 5000u);
}

TEST(FlowTable, RetireCallbackSeesEveryFlowExactlyOnce) {
  FlowTable table({.idle_timeout_ns = 10 * kSec, .max_flows = 2});
  std::vector<std::uint64_t> retired_packets;
  table.set_retire_callback([&](const FlowEntry& e) { retired_packets.push_back(e.total_packets()); });

  auto add_packet = [&](std::uint32_t flow, std::uint64_t ts) {
    FlowEntry* e = table.find_or_create(key_of(flow), Direction::LoToHi, 0, ts).entry;
    e->account(Direction::LoToHi, 10, ts);
  };
  add_packet(0, 0);
  add_packet(0, 1);
  add_packet(1, 2);
  add_packet(2, 3);        // table full: flow 0 (LRU) evicted with 2 packets
  add_packet(1, 20 * kSec);  // flow 1 idle > 10s: retired with 1 packet, restarted
  table.retire_all();      // flows 2 (1 packet) and the new flow 1 (1 packet)

  std::sort(retired_packets.begin(), retired_packets.end());
  EXPECT_EQ(retired_packets, (std::vector<std::uint64_t>{1, 1, 1, 2}));
  EXPECT_EQ(table.size(), 0u);
}

TEST(AppId, NamesRoundTripCaseInsensitively) {
  for (std::size_t i = 0; i < kAppCount; ++i) {
    const auto app = static_cast<AppId>(i);
    EXPECT_EQ(app_from_name(to_string(app)), app);
  }
  EXPECT_EQ(app_from_name("youtube"), AppId::YouTube);
  EXPECT_EQ(app_from_name("GITHUB"), AppId::GitHub);
  EXPECT_FALSE(app_from_name("NotAnApp").has_value());
}

}  // namespace
}  // namespace dpi
