#pragma once

// Minimal byte source/sink abstractions. They let PcapReader/PcapWriter work
// against files in production and against memory in tests and benchmarks
// (where disk I/O would distort the throughput numbers).

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace dpi {

// Thrown for unrecoverable file-level problems (cannot open, bad header,
// I/O error). Per-record problems are reported through return values.
class PcapError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class ByteSource {
 public:
  virtual ~ByteSource() = default;
  // Reads up to out.size() bytes. Returns fewer only at end of input.
  virtual std::size_t read(std::span<std::uint8_t> out) = 0;
};

class ByteSink {
 public:
  virtual ~ByteSink() = default;
  virtual void write(std::span<const std::uint8_t> data) = 0;
  virtual void flush() {}
};

struct FileCloser {
  void operator()(std::FILE* f) const noexcept { std::fclose(f); }
};
using FileHandle = std::unique_ptr<std::FILE, FileCloser>;

class FileSource final : public ByteSource {
 public:
  explicit FileSource(const std::string& path);
  std::size_t read(std::span<std::uint8_t> out) override;

 private:
  FileHandle file_;
  std::string path_;
};

// Non-owning: the caller keeps the buffer alive for the source's lifetime.
class MemorySource final : public ByteSource {
 public:
  explicit MemorySource(std::span<const std::uint8_t> data) noexcept : data_(data) {}
  std::size_t read(std::span<std::uint8_t> out) override;

 private:
  std::span<const std::uint8_t> data_;
  std::size_t pos_ = 0;
};

class FileSink final : public ByteSink {
 public:
  explicit FileSink(const std::string& path);
  void write(std::span<const std::uint8_t> data) override;
  void flush() override;

 private:
  FileHandle file_;
  std::string path_;
};

// Appends to a caller-owned vector.
class MemorySink final : public ByteSink {
 public:
  explicit MemorySink(std::vector<std::uint8_t>& out) noexcept : out_(out) {}
  void write(std::span<const std::uint8_t> data) override;

 private:
  std::vector<std::uint8_t>& out_;
};

// Discards everything but counts bytes, so benchmarks measure the pipeline
// rather than the disk.
class NullSink final : public ByteSink {
 public:
  void write(std::span<const std::uint8_t> data) override { bytes_ += data.size(); }
  std::uint64_t bytes_written() const noexcept { return bytes_; }

 private:
  std::uint64_t bytes_ = 0;
};

// Reads a whole file into memory (used by the benchmark).
std::vector<std::uint8_t> read_whole_file(const std::string& path);

}  // namespace dpi
