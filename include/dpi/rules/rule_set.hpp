#pragma once

#include <bitset>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "dpi/common/types.hpp"

namespace dpi {

// A rule file could not be parsed. what() names the file and line.
class RuleError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// What a rule check needs to know about a flow.
struct FlowFacts {
  std::uint32_t ip_a = 0;
  std::uint32_t ip_b = 0;
  std::uint16_t port_a = 0;
  std::uint16_t port_b = 0;
  AppId app = AppId::Unknown;
  std::string_view host;  // SNI / HTTP Host, empty if unknown
};

// Blocking rules, loaded once and then immutable: the fast-path threads
// share one instance through shared_ptr<const RuleSet> and only ever read
// it, so no locking is needed.
//
// File format, one rule per line ('#' starts a comment, keywords are
// case-insensitive):
//   block ip 192.168.1.50         either endpoint has this address
//   block ip 10.0.0.0/8           ...or is inside this CIDR block
//   block port 6881               either endpoint uses this port
//   block app YouTube             classified as this application
//   block domain example.com      SNI / Host is exactly this name
//   block domain *.tiktok.com     ...this name or any subdomain of it
class RuleSet {
 public:
  RuleSet() = default;

  // `source` is used in error messages (usually the file name).
  static RuleSet parse(std::string_view text, std::string_view source = "<rules>");
  static std::shared_ptr<const RuleSet> load_file(const std::string& path);

  // The first matching rule kind, checked in the order ip, port, app,
  // domain; BlockReason::None if the flow is allowed.
  BlockReason evaluate(const FlowFacts& flow) const;

  bool blocks_ip(std::uint32_t ip) const;
  bool blocks_port(std::uint16_t port) const noexcept { return ports_.test(port); }
  bool blocks_app(AppId app) const noexcept { return apps_.test(static_cast<std::size_t>(app)); }
  bool blocks_host(std::string_view host) const;

  std::size_t size() const noexcept { return rule_count_; }
  bool empty() const noexcept { return rule_count_ == 0; }

 private:
  struct Cidr {
    std::uint32_t network;
    std::uint32_t mask;
  };

  void add_line(std::string_view line, std::string_view source, std::size_t line_number);

  std::unordered_set<std::uint32_t> ips_;
  std::vector<Cidr> cidrs_;
  std::bitset<65536> ports_;
  std::bitset<kAppCount> apps_;
  std::unordered_set<std::string> exact_hosts_;
  std::unordered_set<std::string> host_suffixes_;  // from "*.name" rules
  std::size_t rule_count_ = 0;
};

}  // namespace dpi
