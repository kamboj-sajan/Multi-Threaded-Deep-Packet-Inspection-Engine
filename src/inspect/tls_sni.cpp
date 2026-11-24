#include "dpi/inspect/tls_sni.hpp"

#include "dpi/common/byte_cursor.hpp"
#include "dpi/inspect/hostname.hpp"

namespace dpi {
namespace {

constexpr std::uint8_t kContentHandshake = 0x16;
constexpr std::uint8_t kHandshakeClientHello = 0x01;
// TLSPlaintext is at most 2^14 bytes; allow the 2048 bytes of expansion
// the RFC permits for ciphertext so we never reject a legitimate record.
constexpr std::size_t kMaxRecordLen = (1u << 14) + 2048;
constexpr std::size_t kHandshakeHeaderLen = 4;
constexpr std::size_t kRandomLen = 32;
constexpr std::size_t kMaxSessionIdLen = 32;
constexpr std::uint16_t kExtServerName = 0x0000;
constexpr std::uint8_t kNameTypeHostName = 0;

SniResult result(SniStatus status, std::string sni = {}) { return SniResult{status, std::move(sni)}; }

// server_name extension body: a u16-length list of (u8 type, u16-length name).
// The list must fill the extension exactly.
SniResult parse_server_name(ByteCursor ext) {
  std::uint16_t list_len = 0;
  if (!ext.read_u16(list_len) || list_len != ext.remaining()) {
    return result(SniStatus::Malformed);
  }
  std::optional<ByteCursor> list = ext.sub(list_len);
  while (!list->empty()) {
    std::uint8_t name_type = 0;
    std::uint16_t name_len = 0;
    if (!list->read_u8(name_type) || !list->read_u16(name_len)) {
      return result(SniStatus::Malformed);
    }
    std::optional<ByteCursor> name = list->sub(name_len);
    if (!name) {
      return result(SniStatus::Malformed);
    }
    if (name_type == kNameTypeHostName) {
      const ByteView bytes = name->rest();
      const std::string_view raw(reinterpret_cast<const char*>(bytes.data()), bytes.size());
      std::optional<std::string> host = canonical_hostname(raw);
      return host ? result(SniStatus::Found, std::move(*host)) : result(SniStatus::Malformed);
    }
    // Other name types are unused in practice; skip them per the RFC.
  }
  return result(SniStatus::NoSni);
}

// Walks the ClientHello body (everything after the handshake header).
SniResult parse_hello_body(ByteCursor hello) {
  // legacy_version(2) + random(32)
  if (!hello.skip(2 + kRandomLen)) {
    return result(SniStatus::Malformed);
  }

  std::uint8_t session_id_len = 0;
  if (!hello.read_u8(session_id_len) || session_id_len > kMaxSessionIdLen || !hello.skip(session_id_len)) {
    return result(SniStatus::Malformed);
  }

  // Each cipher suite is 2 bytes and at least one must be offered.
  std::uint16_t cipher_suites_len = 0;
  if (!hello.read_u16(cipher_suites_len) || cipher_suites_len < 2 || cipher_suites_len % 2 != 0 ||
      !hello.skip(cipher_suites_len)) {
    return result(SniStatus::Malformed);
  }

  std::uint8_t compression_len = 0;
  if (!hello.read_u8(compression_len) || compression_len < 1 || !hello.skip(compression_len)) {
    return result(SniStatus::Malformed);
  }

  if (hello.empty()) {
    return result(SniStatus::NoSni);  // extensions are optional (pre-TLS 1.3)
  }
  std::uint16_t extensions_len = 0;
  if (!hello.read_u16(extensions_len)) {
    return result(SniStatus::Malformed);
  }
  // The extension block must end exactly where the ClientHello ends.
  if (extensions_len != hello.remaining()) {
    return result(SniStatus::Malformed);
  }
  ByteCursor extensions = *hello.sub(extensions_len);

  // Walk every extension, not just up to server_name: a hello whose lengths
  // do not add up is corrupt or crafted to evade filtering, and its SNI
  // should not be trusted.
  std::optional<SniResult> server_name;
  while (!extensions.empty()) {
    std::uint16_t type = 0;
    std::uint16_t len = 0;
    if (!extensions.read_u16(type) || !extensions.read_u16(len)) {
      return result(SniStatus::Malformed);
    }
    std::optional<ByteCursor> body = extensions.sub(len);
    if (!body) {
      return result(SniStatus::Malformed);
    }
    if (type == kExtServerName) {
      if (server_name) {
        return result(SniStatus::Malformed);  // duplicates are forbidden (RFC 8446 4.2)
      }
      server_name = parse_server_name(*body);
      if (server_name->status == SniStatus::Malformed) {
        return *server_name;
      }
    }
  }
  return server_name ? *server_name : result(SniStatus::NoSni);
}

}  // namespace

const char* to_string(SniStatus status) noexcept {
  switch (status) {
    case SniStatus::Found: return "found";
    case SniStatus::NoSni: return "no_sni";
    case SniStatus::NotClientHello: return "not_client_hello";
    case SniStatus::Incomplete: return "incomplete";
    case SniStatus::Malformed: return "malformed";
  }
  return "unknown";
}

SniResult parse_tls_client_hello(ByteView payload) {
  ByteCursor cursor(payload);

  // 1. Record header: content type(1) version(2) length(2).
  std::uint8_t content_type = 0;
  if (!cursor.read_u8(content_type)) {
    return result(SniStatus::Incomplete);
  }
  if (content_type != kContentHandshake) {
    return result(SniStatus::NotClientHello);
  }
  std::uint16_t record_version = 0;
  std::uint16_t record_len = 0;
  if (!cursor.read_u16(record_version) || !cursor.read_u16(record_len)) {
    return result(SniStatus::Incomplete);
  }
  // Major version 3 covers SSL 3.0 through TLS 1.3's legacy value.
  if ((record_version >> 8) != 0x03 || (record_version & 0xFF) > 0x04) {
    return result(SniStatus::NotClientHello);
  }
  if (record_len < kHandshakeHeaderLen || record_len > kMaxRecordLen) {
    return result(SniStatus::Malformed);
  }
  // Only a complete record is parsed. Until then, ask for more bytes.
  std::optional<ByteCursor> record = cursor.sub(record_len);
  if (!record) {
    return result(SniStatus::Incomplete);
  }

  // 2. Handshake header: type(1) length(3).
  std::uint8_t handshake_type = 0;
  std::uint32_t handshake_len = 0;
  record->read_u8(handshake_type);  // cannot fail: record_len >= 4
  record->read_u24(handshake_len);
  if (handshake_type != kHandshakeClientHello) {
    return result(SniStatus::NotClientHello);
  }
  std::optional<ByteCursor> hello = record->sub(handshake_len);
  if (!hello) {
    // The handshake message continues in a further TLS record.
    return result(SniStatus::Malformed);
  }

  // 3-7. Version, random, session id, ciphers, compression, extensions.
  return parse_hello_body(*hello);
}

}  // namespace dpi
