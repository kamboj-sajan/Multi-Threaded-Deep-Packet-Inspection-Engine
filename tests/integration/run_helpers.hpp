#pragma once

#include <memory>
#include <string>
#include <vector>

#include "dpi/pcap_io/pcap_reader.hpp"
#include "dpi/pcap_io/pcap_writer.hpp"
#include "dpi/pipeline/engine.hpp"

namespace dpi::test {

inline std::string data_path(const std::string& name) { return std::string(DPI_TEST_DATA_DIR) + "/" + name; }

struct RunOutput {
  RunStats stats;
  std::vector<std::uint8_t> pcap;  // The output capture, in memory.
};

inline RunOutput run_file_sequential(const std::string& name, const EngineConfig& config = {}) {
  RunOutput out;
  PcapReader reader = PcapReader::open_file(data_path(name));
  PcapWriter writer(std::make_unique<MemorySink>(out.pcap), {.precision = reader.info().precision});
  out.stats = run_sequential(reader, writer, config);
  return out;
}

inline std::vector<Packet> read_all(const std::vector<std::uint8_t>& pcap) {
  PcapReader reader(std::make_unique<MemorySource>(pcap));
  std::vector<Packet> packets;
  Packet p;
  while (reader.next(p) == ReadStatus::Ok) {
    packets.push_back(std::move(p));
  }
  return packets;
}

inline std::vector<Packet> read_all_file(const std::string& name) {
  PcapReader reader = PcapReader::open_file(data_path(name));
  std::vector<Packet> packets;
  Packet p;
  while (reader.next(p) == ReadStatus::Ok) {
    packets.push_back(std::move(p));
  }
  return packets;
}

}  // namespace dpi::test
