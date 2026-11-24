#include "dpi/pcap_io/byte_io.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>

namespace dpi {
namespace {

std::string errno_message(const std::string& what, const std::string& path) {
  return what + " '" + path + "': " + std::strerror(errno);
}

}  // namespace

FileSource::FileSource(const std::string& path) : file_(std::fopen(path.c_str(), "rb")), path_(path) {
  if (!file_) {
    throw PcapError(errno_message("cannot open", path));
  }
}

std::size_t FileSource::read(std::span<std::uint8_t> out) {
  const std::size_t n = std::fread(out.data(), 1, out.size(), file_.get());
  if (n < out.size() && std::ferror(file_.get())) {
    throw PcapError(errno_message("read error on", path_));
  }
  return n;
}

std::size_t MemorySource::read(std::span<std::uint8_t> out) {
  const std::size_t n = std::min(out.size(), data_.size() - pos_);
  std::copy_n(data_.begin() + static_cast<std::ptrdiff_t>(pos_), n, out.begin());
  pos_ += n;
  return n;
}

FileSink::FileSink(const std::string& path) : file_(std::fopen(path.c_str(), "wb")), path_(path) {
  if (!file_) {
    throw PcapError(errno_message("cannot create", path));
  }
  // A large stdio buffer turns many small record writes into few syscalls.
  std::setvbuf(file_.get(), nullptr, _IOFBF, 1 << 20);
}

void FileSink::write(std::span<const std::uint8_t> data) {
  if (data.empty()) {
    return;
  }
  if (std::fwrite(data.data(), 1, data.size(), file_.get()) != data.size()) {
    throw PcapError(errno_message("write error on", path_));
  }
}

void FileSink::flush() {
  if (std::fflush(file_.get()) != 0) {
    throw PcapError(errno_message("flush error on", path_));
  }
}

void MemorySink::write(std::span<const std::uint8_t> data) {
  out_.insert(out_.end(), data.begin(), data.end());
}

std::vector<std::uint8_t> read_whole_file(const std::string& path) {
  FileSource source(path);
  std::vector<std::uint8_t> data;
  std::vector<std::uint8_t> chunk(1 << 20);
  while (true) {
    const std::size_t n = source.read(chunk);
    data.insert(data.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(n));
    if (n < chunk.size()) {
      return data;
    }
  }
}

}  // namespace dpi
