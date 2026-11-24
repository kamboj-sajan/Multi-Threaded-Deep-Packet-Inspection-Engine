#include "dpi/rules/rule_set.hpp"

#include <arpa/inet.h>

#include <charconv>
#include <fstream>
#include <sstream>

#include "dpi/inspect/hostname.hpp"

namespace dpi {
namespace {

std::string_view trim(std::string_view s) {
  const auto is_space = [](char c) { return c == ' ' || c == '\t' || c == '\r'; };
  while (!s.empty() && is_space(s.front())) s.remove_prefix(1);
  while (!s.empty() && is_space(s.back())) s.remove_suffix(1);
  return s;
}

std::vector<std::string_view> split_words(std::string_view line) {
  std::vector<std::string_view> words;
  while (true) {
    line = trim(line);
    if (line.empty()) {
      return words;
    }
    const std::size_t end = line.find_first_of(" \t");
    words.push_back(line.substr(0, end));
    if (end == std::string_view::npos) {
      return words;
    }
    line.remove_prefix(end);
  }
}

std::string lower(std::string_view s) {
  std::string out(s);
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return out;
}

std::optional<std::uint32_t> parse_ipv4(std::string_view text) {
  in_addr addr{};
  const std::string copy(text);  // inet_pton needs a NUL-terminated string
  if (inet_pton(AF_INET, copy.c_str(), &addr) != 1) {
    return std::nullopt;
  }
  return ntohl(addr.s_addr);
}

template <typename T>
std::optional<T> parse_number(std::string_view text, T min, T max) {
  T value{};
  const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
  if (ec != std::errc{} || ptr != text.data() + text.size() || value < min || value > max) {
    return std::nullopt;
  }
  return value;
}

std::string all_app_names() {
  std::string names;
  for (std::size_t i = 1; i < kAppCount; ++i) {  // skip "Unknown"
    names += (i > 1 ? ", " : "") + std::string(kAppNames[i]);
  }
  return names;
}

}  // namespace

void RuleSet::add_line(std::string_view line, std::string_view source, std::size_t line_number) {
  const auto fail = [&](const std::string& message) {
    throw RuleError(std::string(source) + ":" + std::to_string(line_number) + ": " + message);
  };

  if (const std::size_t hash = line.find('#'); hash != std::string_view::npos) {
    line = line.substr(0, hash);
  }
  const std::vector<std::string_view> words = split_words(line);
  if (words.empty()) {
    return;  // blank or comment-only line
  }
  if (lower(words[0]) != "block") {
    fail("unknown action '" + std::string(words[0]) + "' (expected 'block')");
  }
  if (words.size() != 3) {
    fail("expected 'block <ip|port|app|domain> <value>'");
  }
  const std::string kind = lower(words[1]);
  const std::string_view value = words[2];

  if (kind == "ip") {
    const std::size_t slash = value.find('/');
    const auto address = parse_ipv4(value.substr(0, slash));
    if (!address) {
      fail("invalid IPv4 address '" + std::string(value) + "'");
    }
    if (slash == std::string_view::npos) {
      ips_.insert(*address);
    } else {
      const auto prefix = parse_number<int>(value.substr(slash + 1), 0, 32);
      if (!prefix) {
        fail("invalid CIDR prefix in '" + std::string(value) + "' (expected /0 to /32)");
      }
      const std::uint32_t mask = *prefix == 0 ? 0 : ~std::uint32_t{0} << (32 - *prefix);
      cidrs_.push_back({*address & mask, mask});
    }
  } else if (kind == "port") {
    const auto port = parse_number<int>(value, 1, 65535);
    if (!port) {
      fail("invalid port '" + std::string(value) + "' (expected 1-65535)");
    }
    ports_.set(static_cast<std::size_t>(*port));
  } else if (kind == "app") {
    const auto app = app_from_name(value);
    if (!app || *app == AppId::Unknown) {
      fail("unknown app '" + std::string(value) + "'; known apps: " + all_app_names());
    }
    apps_.set(static_cast<std::size_t>(*app));
  } else if (kind == "domain") {
    const bool wildcard = value.starts_with("*.");
    const auto host = canonical_hostname(wildcard ? value.substr(2) : value);
    if (!host) {
      fail("invalid domain '" + std::string(value) + "'");
    }
    (wildcard ? host_suffixes_ : exact_hosts_).insert(*host);
  } else {
    fail("unknown rule type '" + std::string(words[1]) + "' (expected ip, port, app or domain)");
  }
  ++rule_count_;
}

RuleSet RuleSet::parse(std::string_view text, std::string_view source) {
  RuleSet rules;
  std::size_t line_number = 0;
  while (!text.empty()) {
    ++line_number;
    const std::size_t newline = text.find('\n');
    rules.add_line(text.substr(0, newline), source, line_number);
    if (newline == std::string_view::npos) {
      break;
    }
    text.remove_prefix(newline + 1);
  }
  return rules;
}

std::shared_ptr<const RuleSet> RuleSet::load_file(const std::string& path) {
  std::ifstream in(path);
  if (!in) {
    throw RuleError("cannot open rules file '" + path + "'");
  }
  std::ostringstream content;
  content << in.rdbuf();
  return std::make_shared<const RuleSet>(parse(content.str(), path));
}

bool RuleSet::blocks_ip(std::uint32_t ip) const {
  if (ips_.contains(ip)) {
    return true;
  }
  for (const Cidr& c : cidrs_) {
    if ((ip & c.mask) == c.network) {
      return true;
    }
  }
  return false;
}

bool RuleSet::blocks_host(std::string_view host) const {
  if (host.empty()) {
    return false;
  }
  if (exact_hosts_.contains(std::string(host))) {
    return true;
  }
  // "*.tiktok.com" covers tiktok.com itself and every name below it; check
  // the host and each parent domain on a label boundary.
  while (true) {
    if (host_suffixes_.contains(std::string(host))) {
      return true;
    }
    const std::size_t dot = host.find('.');
    if (dot == std::string_view::npos) {
      return false;
    }
    host.remove_prefix(dot + 1);
  }
}

BlockReason RuleSet::evaluate(const FlowFacts& flow) const {
  if (blocks_ip(flow.ip_a) || blocks_ip(flow.ip_b)) {
    return BlockReason::Ip;
  }
  if (blocks_port(flow.port_a) || blocks_port(flow.port_b)) {
    return BlockReason::Port;
  }
  if (blocks_app(flow.app)) {
    return BlockReason::App;
  }
  if (blocks_host(flow.host)) {
    return BlockReason::Domain;
  }
  return BlockReason::None;
}

}  // namespace dpi
