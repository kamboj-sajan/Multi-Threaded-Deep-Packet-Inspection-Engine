#pragma once

#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

namespace dpi {

// Fixed-capacity FIFO queue for handing items between threads.
//
// - Bounded: push() blocks while the queue is full. That backpressure keeps
//   a fast producer (the reader) from buffering the whole capture in memory
//   when a downstream stage is slower.
// - Closable: after close(), push() fails and pop() keeps returning items
//   until the queue is empty, then returns nullopt. Consumers therefore
//   drain everything that was accepted and can then exit cleanly.
// - Any number of producers and consumers (MPMC); FIFO order is preserved
//   between any single producer and any single consumer.
//
// Storage is a ring buffer allocated once, so steady-state operation does
// not allocate. Items are moved in and out; T may be move-only.
template <typename T>
class BoundedBlockingQueue {
 public:
  explicit BoundedBlockingQueue(std::size_t capacity) : slots_(capacity) {
    if (capacity == 0) {
      throw std::invalid_argument("BoundedBlockingQueue capacity must be at least 1");
    }
  }

  BoundedBlockingQueue(const BoundedBlockingQueue&) = delete;
  BoundedBlockingQueue& operator=(const BoundedBlockingQueue&) = delete;

  // Blocks while full. Returns false, discarding `item`, if the queue is
  // (or becomes) closed.
  bool push(T item) {
    {
      std::unique_lock lock(mutex_);
      not_full_.wait(lock, [&] { return closed_ || count_ < slots_.size(); });
      if (closed_) {
        return false;
      }
      emplace_locked(std::move(item));
    }
    // Notify after unlocking so the woken consumer does not immediately
    // block on the mutex we still hold.
    not_empty_.notify_one();
    return true;
  }

  // Never blocks. Returns false if the queue is full or closed.
  bool try_push(T item) {
    {
      std::lock_guard lock(mutex_);
      if (closed_ || count_ == slots_.size()) {
        return false;
      }
      emplace_locked(std::move(item));
    }
    not_empty_.notify_one();
    return true;
  }

  // Blocks while empty and open. Returns nullopt once the queue is closed
  // and fully drained.
  std::optional<T> pop() {
    std::optional<T> item;
    {
      std::unique_lock lock(mutex_);
      not_empty_.wait(lock, [&] { return closed_ || count_ > 0; });
      if (count_ == 0) {
        return std::nullopt;  // closed and drained
      }
      item = take_locked();
    }
    not_full_.notify_one();
    return item;
  }

  // Idempotent. Wakes every blocked producer and consumer.
  void close() {
    {
      std::lock_guard lock(mutex_);
      closed_ = true;
    }
    not_full_.notify_all();
    not_empty_.notify_all();
  }

  std::size_t capacity() const noexcept { return slots_.size(); }

  std::size_t size() const {
    std::lock_guard lock(mutex_);
    return count_;
  }

  bool closed() const {
    std::lock_guard lock(mutex_);
    return closed_;
  }

 private:
  void emplace_locked(T&& item) {
    slots_[(head_ + count_) % slots_.size()].emplace(std::move(item));
    ++count_;
  }

  T take_locked() {
    std::optional<T>& slot = slots_[head_];
    T item = std::move(*slot);
    slot.reset();
    head_ = (head_ + 1) % slots_.size();
    --count_;
    return item;
  }

  mutable std::mutex mutex_;
  std::condition_variable not_full_;
  std::condition_variable not_empty_;
  std::vector<std::optional<T>> slots_;
  std::size_t head_ = 0;   // Index of the oldest item.
  std::size_t count_ = 0;  // Number of items stored.
  bool closed_ = false;
};

}  // namespace dpi
