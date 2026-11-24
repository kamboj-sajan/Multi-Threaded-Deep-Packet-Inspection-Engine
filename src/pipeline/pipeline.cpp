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

// Owns every queue, stage object and thread of one run. Each stage object
// is touched only by its own thread while running; the main thread reads
// the stats after join(), which provides the needed happens-before edge.
class Pipeline {
 public:
  Pipeline(PcapReader& reader, PcapWriter& writer, const EngineConfig& config)
      : config_(config), reader_stage_(reader), lbs_(config.num_lbs), writer_stage_(writer),
        writer_queue_(config.queue_capacity) {
    for (std::size_t i = 0; i < config.num_lbs; ++i) {
      lb_queues_.push_back(std::make_unique<BoundedBlockingQueue<RoutedPacket>>(config.queue_capacity));
    }
    for (std::size_t i = 0; i < fp_count(); ++i) {
      fp_queues_.push_back(std::make_unique<BoundedBlockingQueue<WorkItem>>(config.queue_capacity));
      fps_.push_back(std::make_unique<FastPathStage>(config.fast_path));
    }
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
    writer_queue_.close();
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
    writer_queue_.close();
  }

  void reader_loop() {
    RoutedPacket routed;
    while (reader_stage_.next(routed)) {
      const std::size_t lb = lb_index(routed.hash, config_.num_lbs);
      if (!lb_queues_[lb]->push(std::move(routed))) {
        break;  // aborted
      }
    }
    for (auto& q : lb_queues_) {
      q->close();
    }
  }

  void lb_loop(std::size_t lb) {
    LoadBalancerStage& stage = lbs_[lb];
    const std::size_t group_start = lb * config_.fps_per_lb;
    while (std::optional<RoutedPacket> routed = lb_queues_[lb]->pop()) {
      std::optional<WorkItem> item = stage.process(std::move(*routed));
      if (!item) {
        continue;  // malformed: counted and dropped by the stage
      }
      const std::size_t fp = group_start + fp_index_in_group(item->hash, config_.num_lbs, config_.fps_per_lb);
      if (!fp_queues_[fp]->push(std::move(*item))) {
        break;  // aborted
      }
    }
    // This LB is the only producer for its group's queues.
    for (std::size_t i = 0; i < config_.fps_per_lb; ++i) {
      fp_queues_[group_start + i]->close();
    }
  }

  void fp_loop(std::size_t fp) {
    FastPathStage& stage = *fps_[fp];
    while (std::optional<WorkItem> item = fp_queues_[fp]->pop()) {
      if (stage.process(item->packet, item->parsed) == Verdict::Forward &&
          !writer_queue_.push(std::move(item->packet))) {
        break;  // aborted
      }
    }
    stage.finish();
  }

  void writer_loop() {
    while (std::optional<Packet> packet = writer_queue_.pop()) {
      writer_stage_.write(*packet);
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

  std::vector<std::unique_ptr<BoundedBlockingQueue<RoutedPacket>>> lb_queues_;
  std::vector<std::unique_ptr<BoundedBlockingQueue<WorkItem>>> fp_queues_;
  BoundedBlockingQueue<Packet> writer_queue_;
  FailureLatch failure_;
};

void validate(const EngineConfig& config) {
  if (config.num_lbs == 0 || config.fps_per_lb == 0) {
    throw std::invalid_argument("need at least one load balancer and one fast-path thread per LB");
  }
  if (config.queue_capacity == 0) {
    throw std::invalid_argument("queue capacity must be at least 1");
  }
}

}  // namespace

RunStats run_pipeline(PcapReader& reader, PcapWriter& writer, const EngineConfig& config) {
  validate(config);
  Pipeline pipeline(reader, writer, config);
  return pipeline.run();
}

}  // namespace dpi
