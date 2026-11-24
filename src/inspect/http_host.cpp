#include "dpi/inspect/http_host.hpp"

#include <algorithm>
#include <array>
#include <optional>
#include <string_view>

#include "dpi/inspect/hostname.hpp"

namespace dpi {
namespace {

constexpr std::size_t kMaxHeaderBytes = 8192;
constexpr std::array<std::string_view, 9> kMethods = {"GET ",    "POST ",  "HEAD ",  "PUT ",  "DELETE ",
                                                      "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "};

HttpHostResult result(HttpHostStatus status, std::string host = {}) {
  return HttpHostResult{status, std::move(host)};
}

bool equals_ignore_case(std::string_view a, std::string_view b) {
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
           const auto lower = [](char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; };
           return lower(x) == lower(y);
         });
}

std::string_view trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
  return s;
}

// Returns the next line (without CR LF) and advances `text`, or nullopt if
// no complete line is available yet.
std::optional<std::string_view> next_line(std::string_view& text) {
  const std::size_t lf = text.find('\n');
  if (lf == std::string_view::npos) {
    return std::nullopt;
  }
  std::string_view line = text.substr(0, lf);
  text.remove_prefix(lf + 1);
  if (!line.empty() && line.back() == '\r') {
    line.remove_suffix(1);
  }
  return line;
}

// "example.com:8080" -> "example.com". IPv6 literals ("[::1]:80") are not
// host names; they are reported as no usable host.
std::optional<std::string> host_from_header_value(std::string_view value) {
  if (!value.empty() && value.front() == '[') {
    return std::nullopt;
  }
  if (const std::size_t colon = value.rfind(':'); colon != std::string_view::npos) {
    const std::string_view port = value.substr(colon + 1);
    if (port.empty() || !std::all_of(port.begin(), port.end(), [](char c) { return c >= '0' && c <= '9'; })) {
      return std::nullopt;
    }
    value = value.substr(0, colon);
  }
  return canonical_hostname(value);
}

}  // namespace

const char* to_string(HttpHostStatus status) noexcept {
  switch (status) {
    case HttpHostStatus::Found: return "found";
    case HttpHostStatus::NoHost: return "no_host";
    case HttpHostStatus::NotHttp: return "not_http";
    case HttpHostStatus::Incomplete: return "incomplete";
  }
  return "unknown";
}

HttpHostResult parse_http_host(ByteView payload) {
  const ByteView limited = payload.first(std::min(payload.size(), kMaxHeaderBytes));
  std::string_view text(reinterpret_cast<const char*>(limited.data()), limited.size());
  const bool may_grow = payload.size() < kMaxHeaderBytes;  // more bytes could still arrive

  const bool method_ok = std::any_of(kMethods.begin(), kMethods.end(), [&](std::string_view m) {
    return text.starts_with(m);
  });
  if (!method_ok) {
    // A short payload that is a prefix of a method might be a request
    // split very early; anything else is not HTTP.
    const bool prefix = std::any_of(kMethods.begin(), kMethods.end(), [&](std::string_view m) {
      return text.size() < m.size() && m.starts_with(text);
    });
    return result(prefix && may_grow ? HttpHostStatus::Incomplete : HttpHostStatus::NotHttp);
  }

  const std::optional<std::string_view> request_line = next_line(text);
  if (!request_line) {
    return result(may_grow ? HttpHostStatus::Incomplete : HttpHostStatus::NotHttp);
  }
  if (request_line->find(" HTTP/1.") == std::string_view::npos) {
    return result(HttpHostStatus::NotHttp);  // HTTP/0.9, HTTP/2 preface or garbage
  }

  while (const std::optional<std::string_view> line = next_line(text)) {
    if (line->empty()) {
      return result(HttpHostStatus::NoHost);  // end of headers
    }
    const std::size_t colon = line->find(':');
    if (colon == std::string_view::npos) {
      continue;  // tolerate a malformed header line
    }
    if (equals_ignore_case(trim(line->substr(0, colon)), "host")) {
      std::optional<std::string> host = host_from_header_value(trim(line->substr(colon + 1)));
      return host ? result(HttpHostStatus::Found, std::move(*host)) : result(HttpHostStatus::NoHost);
    }
  }
  // Headers end beyond what we have: wait for more, unless we already
  // examined as much as we are willing to.
  return result(may_grow ? HttpHostStatus::Incomplete : HttpHostStatus::NoHost);
}

}  // namespace dpi
