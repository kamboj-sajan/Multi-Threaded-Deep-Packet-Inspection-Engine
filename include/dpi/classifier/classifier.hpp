#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

#include "dpi/common/types.hpp"

namespace dpi {

// One row of the domain table: a host matches if it equals `suffix` or ends
// with "." + suffix.
struct DomainRule {
  std::string_view suffix;
  AppId app;
};

// Maps host names (from SNI / HTTP Host) to applications, falling back to
// well-known ports. Immutable after construction, so one instance can be
// shared by every thread.
class Classifier {
 public:
  Classifier();  // the built-in table
  explicit Classifier(std::span<const DomainRule> table);

  // Longest matching suffix wins ("r4.googlevideo.com" is YouTube, not
  // Google). Matching is on label boundaries, so "netflix.com" does not
  // match the suffix "x.com". `host` must already be canonical (lower case).
  // Returns AppId::Unknown when nothing matches.
  AppId app_for_host(std::string_view host) const;

  // Port-based guess used when payload inspection gives no host.
  static AppId app_for_port(std::uint8_t protocol, std::uint16_t server_port) noexcept;

  static std::span<const DomainRule> builtin_table() noexcept;

  // Shared instance with the built-in table (thread-safe initialisation).
  static const Classifier& builtin();

 private:
  std::unordered_map<std::string, AppId> by_suffix_;
};

}  // namespace dpi
