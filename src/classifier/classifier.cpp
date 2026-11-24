#include "dpi/classifier/classifier.hpp"

#include <array>

namespace dpi {
namespace {

// The data that drives classification. Adding an application is a matter
// of adding rows here (and an AppId). std::to_array deduces the size, so a
// row count can never drift out of sync with the rows.
constexpr auto kBuiltinTable = std::to_array<DomainRule>({
    {"youtube.com", AppId::YouTube},        {"googlevideo.com", AppId::YouTube},
    {"ytimg.com", AppId::YouTube},          {"youtu.be", AppId::YouTube},
    {"youtube-nocookie.com", AppId::YouTube}, {"youtubei.googleapis.com", AppId::YouTube},

    {"netflix.com", AppId::Netflix},        {"netflix.net", AppId::Netflix},
    {"nflxvideo.net", AppId::Netflix},      {"nflximg.net", AppId::Netflix},
    {"nflxext.com", AppId::Netflix},        {"nflxso.net", AppId::Netflix},

    {"facebook.com", AppId::Facebook},      {"fbcdn.net", AppId::Facebook},
    {"fb.com", AppId::Facebook},            {"facebook.net", AppId::Facebook},
    {"fbsbx.com", AppId::Facebook},         {"messenger.com", AppId::Facebook},

    {"instagram.com", AppId::Instagram},    {"cdninstagram.com", AppId::Instagram},

    {"whatsapp.com", AppId::WhatsApp},      {"whatsapp.net", AppId::WhatsApp},
    {"wa.me", AppId::WhatsApp},

    {"google.com", AppId::Google},          {"googleapis.com", AppId::Google},
    {"gstatic.com", AppId::Google},         {"googleusercontent.com", AppId::Google},
    {"gmail.com", AppId::Google},           {"google-analytics.com", AppId::Google},
    {"googletagmanager.com", AppId::Google}, {"doubleclick.net", AppId::Google},

    {"github.com", AppId::GitHub},          {"githubusercontent.com", AppId::GitHub},
    {"githubassets.com", AppId::GitHub},    {"github.io", AppId::GitHub},

    {"tiktok.com", AppId::TikTok},          {"tiktokcdn.com", AppId::TikTok},
    {"tiktokv.com", AppId::TikTok},         {"byteoversea.com", AppId::TikTok},
    {"ttwstatic.com", AppId::TikTok},

    {"twitter.com", AppId::Twitter},        {"x.com", AppId::Twitter},
    {"twimg.com", AppId::Twitter},          {"t.co", AppId::Twitter},

    {"amazon.com", AppId::Amazon},          {"amazonaws.com", AppId::Amazon},
    {"media-amazon.com", AppId::Amazon},    {"primevideo.com", AppId::Amazon},

    {"microsoft.com", AppId::Microsoft},    {"live.com", AppId::Microsoft},
    {"office.com", AppId::Microsoft},       {"windows.net", AppId::Microsoft},
    {"bing.com", AppId::Microsoft},         {"outlook.com", AppId::Microsoft},

    {"apple.com", AppId::Apple},            {"icloud.com", AppId::Apple},
    {"mzstatic.com", AppId::Apple},         {"apple-cloudkit.com", AppId::Apple},

    {"cloudflare.com", AppId::Cloudflare},  {"cloudflare-dns.com", AppId::Cloudflare},

    {"spotify.com", AppId::Spotify},        {"scdn.co", AppId::Spotify},
    {"spotifycdn.com", AppId::Spotify},

    {"zoom.us", AppId::Zoom},               {"zoom.com", AppId::Zoom},

    {"discord.com", AppId::Discord},        {"discord.gg", AppId::Discord},
    {"discordapp.com", AppId::Discord},     {"discordapp.net", AppId::Discord},

    {"telegram.org", AppId::Telegram},      {"t.me", AppId::Telegram},
    {"telegram.me", AppId::Telegram},
});

}  // namespace

Classifier::Classifier() : Classifier(builtin_table()) {}

Classifier::Classifier(std::span<const DomainRule> table) {
  for (const DomainRule& rule : table) {
    by_suffix_.emplace(std::string(rule.suffix), rule.app);
  }
}

std::span<const DomainRule> Classifier::builtin_table() noexcept { return kBuiltinTable; }

const Classifier& Classifier::builtin() {
  static const Classifier instance;
  return instance;
}

AppId Classifier::app_for_host(std::string_view host) const {
  // Try the whole name, then drop one leading label at a time:
  // "a.b.youtube.com" -> "b.youtube.com" -> "youtube.com" -> "com".
  // The first hit is therefore the longest matching suffix, and every
  // candidate starts on a label boundary.
  while (!host.empty()) {
    if (const auto it = by_suffix_.find(std::string(host)); it != by_suffix_.end()) {
      return it->second;
    }
    const std::size_t dot = host.find('.');
    if (dot == std::string_view::npos) {
      break;
    }
    host.remove_prefix(dot + 1);
  }
  return AppId::Unknown;
}

AppId Classifier::app_for_port(std::uint8_t protocol, std::uint16_t server_port) noexcept {
  constexpr std::uint8_t kTcp = 6;
  constexpr std::uint8_t kUdp = 17;
  if (protocol == kTcp) {
    switch (server_port) {
      case 443: return AppId::HTTPS;
      case 80:
      case 8080: return AppId::HTTP;
      case 53: return AppId::DNS;
      case 22: return AppId::SSH;
      default: return AppId::Unknown;
    }
  }
  if (protocol == kUdp) {
    switch (server_port) {
      case 53: return AppId::DNS;
      case 443: return AppId::QUIC;  // QUIC payloads are not inspected
      case 123: return AppId::NTP;
      default: return AppId::Unknown;
    }
  }
  return AppId::Unknown;
}

}  // namespace dpi
