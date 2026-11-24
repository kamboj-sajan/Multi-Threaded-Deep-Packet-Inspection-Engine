#pragma once

// Small vocabulary types shared by the flow, classifier, rules and engine
// layers. Kept here so that lower layers (flow) need not depend on higher
// ones (classifier) just to name an application.

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace dpi {

enum class Verdict : std::uint8_t { Forward, Drop };

inline constexpr const char* to_string(Verdict v) noexcept {
  return v == Verdict::Forward ? "forward" : "drop";
}

// Applications the classifier can name. HTTPS / HTTP / DNS / QUIC are the
// port-based fallbacks used when no domain matched.
enum class AppId : std::uint8_t {
  Unknown,
  HTTP,
  HTTPS,
  DNS,
  QUIC,
  SSH,
  NTP,
  YouTube,
  Netflix,
  Facebook,
  Instagram,
  WhatsApp,
  Google,
  GitHub,
  TikTok,
  Twitter,
  Amazon,
  Microsoft,
  Apple,
  Cloudflare,
  Spotify,
  Zoom,
  Discord,
  Telegram,
};

inline constexpr std::array<std::string_view, 24> kAppNames = {
    "Unknown", "HTTP",      "HTTPS",    "DNS",    "QUIC",      "SSH",
    "NTP",     "YouTube",   "Netflix",  "Facebook", "Instagram", "WhatsApp",
    "Google",  "GitHub",    "TikTok",   "Twitter",  "Amazon",    "Microsoft",
    "Apple",   "Cloudflare", "Spotify", "Zoom",     "Discord",   "Telegram",
};
inline constexpr std::size_t kAppCount = kAppNames.size();
static_assert(static_cast<std::size_t>(AppId::Telegram) + 1 == kAppCount,
              "kAppNames must list every AppId in order");

inline constexpr std::string_view to_string(AppId app) noexcept {
  return kAppNames[static_cast<std::size_t>(app)];
}

// Case-insensitive lookup, used when parsing rule files ("block app youtube").
inline std::optional<AppId> app_from_name(std::string_view name) noexcept {
  const auto equal_ci = [](std::string_view a, std::string_view b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
             return std::tolower(static_cast<unsigned char>(x)) ==
                    std::tolower(static_cast<unsigned char>(y));
           });
  };
  for (std::size_t i = 0; i < kAppCount; ++i) {
    if (equal_ci(kAppNames[i], name)) {
      return static_cast<AppId>(i);
    }
  }
  return std::nullopt;
}

}  // namespace dpi
