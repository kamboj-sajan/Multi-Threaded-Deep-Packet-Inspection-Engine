#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <thread>
#include <vector>

#include "dpi/concurrency/bounded_queue.hpp"

namespace dpi {
namespace {

using namespace std::chrono_literals;

TEST(BoundedQueue, IsFifo) {
  BoundedBlockingQueue<int> q(4);
  for (int i = 0; i < 4; ++i) {
    ASSERT_TRUE(q.push(i));
  }
  for (int i = 0; i < 4; ++i) {
    EXPECT_EQ(q.pop(), i);
  }
}

TEST(BoundedQueue, WrapsAroundTheRingBuffer) {
  BoundedBlockingQueue<int> q(3);
  for (int round = 0; round < 10; ++round) {
    ASSERT_TRUE(q.push(round * 2));
    ASSERT_TRUE(q.push(round * 2 + 1));
    EXPECT_EQ(q.pop(), round * 2);
    EXPECT_EQ(q.pop(), round * 2 + 1);
  }
  EXPECT_EQ(q.size(), 0u);
}

TEST(BoundedQueue, RejectsZeroCapacity) {
  EXPECT_THROW(BoundedBlockingQueue<int>(0), std::invalid_argument);
}

TEST(BoundedQueue, TryPushFailsWhenFull) {
  BoundedBlockingQueue<int> q(2);
  EXPECT_TRUE(q.try_push(1));
  EXPECT_TRUE(q.try_push(2));
  EXPECT_FALSE(q.try_push(3));
  EXPECT_EQ(q.size(), 2u);
}

TEST(BoundedQueue, SupportsMoveOnlyItems) {
  BoundedBlockingQueue<std::unique_ptr<int>> q(1);
  ASSERT_TRUE(q.push(std::make_unique<int>(42)));
  auto item = q.pop();
  ASSERT_TRUE(item.has_value());
  EXPECT_EQ(**item, 42);
}

TEST(BoundedQueue, PushBlocksUntilSpaceIsFreed) {
  BoundedBlockingQueue<int> q(1);
  ASSERT_TRUE(q.push(1));
  std::atomic<bool> pushed{false};
  std::thread producer([&] {
    EXPECT_TRUE(q.push(2));  // blocks: queue is full
    pushed = true;
  });
  std::this_thread::sleep_for(50ms);
  EXPECT_FALSE(pushed.load());  // still blocked (backpressure)
  EXPECT_EQ(q.pop(), 1);        // frees a slot
  producer.join();
  EXPECT_TRUE(pushed.load());
  EXPECT_EQ(q.pop(), 2);
}

TEST(BoundedQueue, CloseLetsConsumersDrainThenStop) {
  BoundedBlockingQueue<int> q(8);
  ASSERT_TRUE(q.push(1));
  ASSERT_TRUE(q.push(2));
  q.close();
  EXPECT_FALSE(q.push(3));  // no new items after close
  EXPECT_EQ(q.pop(), 1);    // ...but accepted items are still delivered
  EXPECT_EQ(q.pop(), 2);
  EXPECT_EQ(q.pop(), std::nullopt);
  EXPECT_EQ(q.pop(), std::nullopt);
  q.close();  // idempotent
  EXPECT_TRUE(q.closed());
}

TEST(BoundedQueue, CloseWakesBlockedConsumers) {
  BoundedBlockingQueue<int> q(1);
  std::vector<std::thread> consumers;
  std::atomic<int> finished{0};
  for (int i = 0; i < 3; ++i) {
    consumers.emplace_back([&] {
      EXPECT_EQ(q.pop(), std::nullopt);
      ++finished;
    });
  }
  std::this_thread::sleep_for(20ms);
  q.close();
  for (auto& t : consumers) {
    t.join();
  }
  EXPECT_EQ(finished.load(), 3);
}

TEST(BoundedQueue, CloseWakesBlockedProducers) {
  BoundedBlockingQueue<int> q(1);
  ASSERT_TRUE(q.push(0));
  std::thread producer([&] { EXPECT_FALSE(q.push(1)); });
  std::this_thread::sleep_for(20ms);
  q.close();
  producer.join();
  EXPECT_EQ(q.pop(), 0);
  EXPECT_EQ(q.pop(), std::nullopt);
}

// Several producers and consumers hammer a tiny queue. Every item must be
// delivered exactly once, and each consumer must see each producer's items
// in the order they were pushed.
TEST(BoundedQueue, MpmcStressLosesAndDuplicatesNothing) {
  constexpr int kProducers = 4;
  constexpr int kConsumers = 4;
  constexpr std::uint32_t kPerProducer = 50'000;
  BoundedBlockingQueue<std::uint64_t> q(8);  // small: forces constant blocking

  std::vector<std::vector<std::uint64_t>> received(kConsumers);
  std::vector<std::thread> consumers;
  for (int c = 0; c < kConsumers; ++c) {
    consumers.emplace_back([&, c] {
      while (auto item = q.pop()) {
        received[c].push_back(*item);
      }
    });
  }
  std::vector<std::thread> producers;
  for (std::uint64_t p = 0; p < kProducers; ++p) {
    producers.emplace_back([&, p] {
      for (std::uint64_t i = 0; i < kPerProducer; ++i) {
        ASSERT_TRUE(q.push((p << 32) | i));
      }
    });
  }
  for (auto& t : producers) {
    t.join();
  }
  q.close();
  for (auto& t : consumers) {
    t.join();
  }

  std::vector<std::uint64_t> all;
  for (const auto& per_consumer : received) {
    // Per-producer FIFO as observed by this consumer.
    std::vector<std::int64_t> last(kProducers, -1);
    for (const std::uint64_t item : per_consumer) {
      const auto producer = static_cast<std::size_t>(item >> 32);
      const auto index = static_cast<std::int64_t>(item & 0xFFFFFFFFu);
      ASSERT_GT(index, last[producer]);
      last[producer] = index;
    }
    all.insert(all.end(), per_consumer.begin(), per_consumer.end());
  }
  ASSERT_EQ(all.size(), std::size_t{kProducers} * kPerProducer);
  std::sort(all.begin(), all.end());
  EXPECT_EQ(std::adjacent_find(all.begin(), all.end()), all.end()) << "duplicate item";
  for (std::uint64_t p = 0; p < kProducers; ++p) {
    for (std::uint64_t i = 0; i < kPerProducer; i += 9973) {
      EXPECT_TRUE(std::binary_search(all.begin(), all.end(), (p << 32) | i));
    }
  }
}

}  // namespace
}  // namespace dpi
