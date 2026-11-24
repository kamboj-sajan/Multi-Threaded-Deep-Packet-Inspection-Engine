#include <algorithm>
#include <chrono>
#include <exception>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

#include "dpi/concurrency/bounded_queue.hpp"
#include "dpi/pipeline/engine.hpp"

namespace dpi {
namespace {

// Records the first exception thrown by any thread.
class FailureLatch {
 public:
  void record(std::exception_ptr error) {
    std::lock_guard lock(mutex_);
    if (!first_) {
      first_ = std::move(error);
    }
  }
  void rethrow_if_failed() {
    std::lock_guard lock(mutex_);
    if (first_) {
      std::rethrow_exception(first_);
    }
  }

 private:
  std::mutex mutex_;
  std::exception_ptr first_;
};

// Units handed between threads. Batching amortises the queue's lock and
// condition-variable wake-up over many packets: per packet, that hand-off
// costs far more than the stage work itself.
using RoutedBatch = std::vector<RoutedPacket>;
using WorkBatch = std::vector<WorkItem>;
using PacketBatch = std::vector<Packet>;

// Collects items per destination queue and pushes each batch when it is
// full or when flushed. Returns false from add/flush once the run aborted.
template <typename Item>
class Batcher {
 public:
  Batcher(std::vector<std::unique_ptr<BoundedBlockingQueue<std::vector<Item>>>>& queues, std::size_t first,
          std::size_t count, std::size_t batch_size)
      : queues_(queues), first_(first), batch_size_(batch_size), pending_(count) {}

  bool add(std::size_t destination, Item&& item) {
    std::vector<Item>& batch = pending_[destination];
    if (batch.empty()) {
      batch.reserve(batch_size_);
    }
    batch.push_back(std::move(item));
    return batch.size() < batch_size_ || send(destination);
  }

  bool flush() {
    for (std::size_t d = 0; d < pending_.size(); ++d) {
      if (!pending_[d].empty() && !send(d)) {
        return false;
      }
    }
    return true;
  }

 private:
  bool send(std::size_t destination) {
    std::vector<Item> batch;
    batch.swap(pending_[destination]);
    return queues_[first_ + destination]->push(std::move(batch));
  }

  std::vector<std::unique_ptr<BoundedBlockingQueue<std::vector<Item>>>>& queues_;
  std::size_t first_;
  std::size_t batch_size_;
  std::vector<std::vector<Item>> pending_;
};

// Owns every queue, stage object and thread of one run. Each stage object
// is touched only by its own thread while running; the main thread reads
// the stats after join(), which provides the needed happens-before edge.
class Pipeline {
 public:
  Pipeline(PcapReader& reader, PcapWriter& writer, const EngineConfig& config)
      : config_(config), reader_stage_(reader), lbs_(config.num_lbs), writer_stage_(writer) {
    // Queues hold batches; size them so each holds about queue_capacity
    // packets.
    const std::size_t batches = std::max<std::size_t>(1, config.queue_capacity / config.batch_size);
    for (std::size_t i = 0; i < config.num_lbs; ++i) {
      lb_queues_.push_back(std::make_unique<BoundedBlockingQueue<RoutedBatch>>(batches));
    }
    for (std::size_t i = 0; i < fp_count(); ++i) {
      fp_queues_.push_back(std::make_unique<BoundedBlockingQueue<WorkBatch>>(batches));
      fps_.push_back(std::make_unique<FastPathStage>(config.fast_path));
    }
    writer_queue_.push_back(std::make_unique<BoundedBlockingQueue<PacketBatch>>(batches));
  }

  RunStats run() {
    const auto start = std::chrono::steady_clock::now();

    // Threads are stored in pipeline order: reader, LBs, FPs, writer.
    std::vector<std::thread> threads;
    try {
      threads.push_back(spawn([this] { reader_loop(); }));
      for (std::size_t i = 0; i < config_.num_lbs; ++i) {
        threads.push_back(spawn([this, i] { lb_loop(i); }));
      }
      for (std::size_t i = 0; i < fp_count(); ++i) {
        threads.push_back(spawn([this, i] { fp_loop(i); }));
      }
      threads.push_back(spawn([this] { writer_loop(); }));
    } catch (...) {
      // Could not start every thread: stop the ones that did start.
      abort_all();
      for (std::thread& t : threads) {
        t.join();
      }
      throw;
    }

    // Ordered shutdown. Each stage closes its downstream queues when its
    // input is exhausted (reader -> LB queues, LB -> its own FP queues), so
    // joining upstream-first lets each stage drain completely. The writer
    // queue has many producers, so it is closed here, once every FP has
    // finished.
    for (std::size_t i = 0; i + 1 < threads.size(); ++i) {
      threads[i].join();
    }
    writer_queue_[0]->close();
    threads.back().join();

    failure_.rethrow_if_failed();
    return collect_stats(std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count());
  }

 private:
  std::size_t fp_count() const noexcept { return config_.num_lbs * config_.fps_per_lb; }

  // Starts a thread whose exceptions abort the whole run instead of
  // calling std::terminate or leaving other threads blocked forever.
  template <typename Body>
  std::thread spawn(Body body) {
    return std::thread([this, body] {
      try {
        body();
      } catch (...) {
        failure_.record(std::current_exception());
        abort_all();
      }
    });
  }

  // Closing every queue makes all blocked push/pop calls return, so every
  // thread reaches its exit path.
  void abort_all() {
    for (auto& q : lb_queues_) {
      q->close();
    }
    for (auto& q : fp_queues_) {
      q->close();
    }
    writer_queue_[0]->close();
  }

  void reader_loop() {
    Batcher<RoutedPacket> out(lb_queues_, 0, config_.num_lbs, config_.batch_size);
    RoutedPacket routed;
    bool ok = true;
    while (ok && reader_stage_.next(routed)) {
      const std::size_t lb = lb_index(routed.hash, config_.num_lbs);
      ok = out.add(lb, std::move(routed));
    }
    if (ok) {
      out.flush();
    }
    for (auto& q : lb_queues_) {
      q->close();
    }
  }

  void lb_loop(std::size_t lb) {
    LoadBalancerStage& stage = lbs_[lb];
    const std::size_t group_start = lb * config_.fps_per_lb;
    Batcher<WorkItem> out(fp_queues_, group_start, config_.fps_per_lb, config_.batch_size);
    bool ok = true;
    while (ok) {
      std::optional<RoutedBatch> batch = lb_queues_[lb]->pop();
      if (!batch) {
        break;
      }
      for (RoutedPacket& routed : *batch) {
        std::optional<WorkItem> item = stage.process(std::move(routed));
        if (!item) {
          continue;  // malformed: counted and dropped by the stage
        }
        const std::size_t fp = fp_index_in_group(item->hash, config_.num_lbs, config_.fps_per_lb);
        if (!(ok = out.add(fp, std::move(*item)))) {
          break;  // aborted
        }
      }
      // Flush after every input batch so packets never wait for more
      // traffic to the same FP; latency stays bounded by one batch.
      ok = ok && out.flush();
    }
    // This LB is the only producer for its group's queues.
    for (std::size_t i = 0; i < config_.fps_per_lb; ++i) {
      fp_queues_[group_start + i]->close();
    }
  }

  void fp_loop(std::size_t fp) {
    FastPathStage& stage = *fps_[fp];
    Batcher<Packet> out(writer_queue_, 0, 1, config_.batch_size);
    bool ok = true;
    while (ok) {
      std::optional<WorkBatch> batch = fp_queues_[fp]->pop();
      if (!batch) {
        break;
      }
      for (WorkItem& item : *batch) {
        if (stage.process(item.packet, item.parsed) == Verdict::Forward && !(ok = out.add(0, std::move(item.packet)))) {
          break;  // aborted
        }
      }
      ok = ok && out.flush();
    }
    stage.finish();
  }

  void writer_loop() {
    while (std::optional<PacketBatch> batch = writer_queue_[0]->pop()) {
      for (const Packet& packet : *batch) {
        writer_stage_.write(packet);
      }
    }
    writer_stage_.finish();
  }

  RunStats collect_stats(double elapsed_seconds) const {
    RunStats stats;
    stats.num_lbs = config_.num_lbs;
    stats.fps_per_lb = config_.fps_per_lb;
    stats.reader = reader_stage_.stats();
    for (const LoadBalancerStage& lb : lbs_) {
      stats.lbs.push_back(lb.stats());
    }
    for (const auto& fp : fps_) {
      stats.fps.push_back(fp->stats());
    }
    stats.writer = writer_stage_.stats();
    stats.elapsed_seconds = elapsed_seconds;
    return stats;
  }

  const EngineConfig& config_;
  ReaderStage reader_stage_;
  std::vector<LoadBalancerStage> lbs_;
  std::vector<std::unique_ptr<FastPathStage>> fps_;
  WriterStage writer_stage_;

  std::vector<std::unique_ptr<BoundedBlockingQueue<RoutedBatch>>> lb_queues_;
  std::vector<std::unique_ptr<BoundedBlockingQueue<WorkBatch>>> fp_queues_;
  // A vector of one queue, so Batcher can address it like the others.
  std::vector<std::unique_ptr<BoundedBlockingQueue<PacketBatch>>> writer_queue_;
  FailureLatch failure_;
};

void validate(const EngineConfig& config) {
  if (config.num_lbs == 0 || config.fps_per_lb == 0) {
    throw std::invalid_argument("need at least one load balancer and one fast-path thread per LB");
  }
  if (config.queue_capacity == 0) {
    throw std::invalid_argument("queue capacity must be at least 1");
  }
  if (config.batch_size == 0) {
    throw std::invalid_argument("batch size must be at least 1");
  }
}

}  // namespace

RunStats run_pipeline(PcapReader& reader, PcapWriter& writer, const EngineConfig& config) {
  validate(config);
  Pipeline pipeline(reader, writer, config);
  return pipeline.run();
}

}  // namespace dpi
