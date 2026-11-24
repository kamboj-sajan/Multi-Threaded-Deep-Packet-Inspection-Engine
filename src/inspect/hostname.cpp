#include "dpi/inspect/hostname.hpp"

namespace dpi {
namespace {

constexpr std::size_t kMaxHostnameLen = 253;

bool is_hostname_char(char c) noexcept {
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
}

}  // namespace

std::optional<std::string> canonical_hostname(std::string_view raw) {
  if (!raw.empty() && raw.back() == '.') {
    raw.remove_suffix(1);  // "example.com." is the same name
  }
  if (raw.empty() || raw.size() > kMaxHostnameLen) {
    return std::nullopt;
  }
  std::string host(raw);
  char previous = '.';  // treat the start like a label boundary
  for (char& c : host) {
    if (c >= 'A' && c <= 'Z') {
      c = static_cast<char>(c - 'A' + 'a');
    }
    if (!is_hostname_char(c) || (c == '.' && previous == '.')) {
      return std::nullopt;  // bad character, leading dot or empty label
    }
    previous = c;
  }
  return host;
}

}  // namespace dpi
