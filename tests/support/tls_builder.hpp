#pragma once

// Builds TLS ClientHello records for tests, remembering where each length
// field lives so tests can corrupt them one at a time.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "packet_builder.hpp"

namespace dpi::test {

struct HelloSpec {
  std::optional<std::string> sni = std::string("www.example.com");
  std::uint8_t content_type = 0x16;
  std::uint16_t record_version = 0x0301;
  std::uint8_t handshake_type = 0x01;
  std::uint8_t session_id_len = 32;
  std::uint16_t cipher_suites = 3;
  std::uint8_t compression_methods = 1;
  bool include_extensions = true;
  int extensions_before_sni = 2;
  int extensions_after_sni = 2;
  bool non_host_name_entry_first = false;  // server_name list starts with type 1
};

struct HelloLayout {
  Bytes bytes;
  std::size_t record_len = 0;      // offset of each length field
  std::size_t handshake_len = 0;
  std::size_t session_id_len = 0;
  std::size_t cipher_suites_len = 0;
  std::size_t compression_len = 0;
  std::size_t extensions_len = 0;
  std::size_t sni_ext_len = 0;
  std::size_t sni_list_len = 0;
  std::size_t sni_name_len = 0;
};

inline void put24(Bytes& b, std::uint32_t v) {
  put8(b, static_cast<std::uint8_t>(v >> 16));
  put16(b, static_cast<std::uint16_t>(v));
}

inline void set16(Bytes& b, std::size_t at, std::uint16_t v) {
  b[at] = static_cast<std::uint8_t>(v >> 8);
  b[at + 1] = static_cast<std::uint8_t>(v);
}

inline HelloLayout build_client_hello(const HelloSpec& s) {
  HelloLayout h;
  Bytes& b = h.bytes;
  put8(b, s.content_type);
  put16(b, s.record_version);
  h.record_len = b.size();
  put16(b, 0);  // patched below
  put8(b, s.handshake_type);
  h.handshake_len = b.size();
  put24(b, 0);  // patched below
  const std::size_t body_start = b.size();

  put16(b, 0x0303);
  for (int i = 0; i < 32; ++i) put8(b, static_cast<std::uint8_t>(i));  // random
  h.session_id_len = b.size();
  put8(b, s.session_id_len);
  for (int i = 0; i < s.session_id_len; ++i) put8(b, 0xEE);
  h.cipher_suites_len = b.size();
  put16(b, static_cast<std::uint16_t>(2 * s.cipher_suites));
  for (int i = 0; i < s.cipher_suites; ++i) put16(b, static_cast<std::uint16_t>(0x1301 + i));
  h.compression_len = b.size();
  put8(b, s.compression_methods);
  for (int i = 0; i < s.compression_methods; ++i) put8(b, 0);

  if (s.include_extensions) {
    h.extensions_len = b.size();
    put16(b, 0);  // patched below
    const std::size_t ext_start = b.size();
    auto filler = [&](int n, std::uint16_t base) {
      for (int i = 0; i < n; ++i) {
        // Private-use types; wrap within 256 so the type can never reach
        // 0x0000 (server_name) however many fillers are requested.
        put16(b, static_cast<std::uint16_t>(base + (i % 256)));
        put16(b, 2);
        put16(b, 0xABCD);
      }
    };
    filler(s.extensions_before_sni, 0xFE00);
    if (s.sni) {
      put16(b, 0x0000);
      h.sni_ext_len = b.size();
      put16(b, 0);
      const std::size_t sni_start = b.size();
      h.sni_list_len = b.size();
      put16(b, 0);
      const std::size_t list_start = b.size();
      if (s.non_host_name_entry_first) {
        put8(b, 1);
        put16(b, 3);
        put8(b, 'a'); put8(b, 'b'); put8(b, 'c');
      }
      put8(b, 0);  // host_name
      h.sni_name_len = b.size();
      put16(b, static_cast<std::uint16_t>(s.sni->size()));
      for (char c : *s.sni) put8(b, static_cast<std::uint8_t>(c));
      set16(b, h.sni_list_len, static_cast<std::uint16_t>(b.size() - list_start));
      set16(b, h.sni_ext_len, static_cast<std::uint16_t>(b.size() - sni_start));
    }
    filler(s.extensions_after_sni, 0xFF00);
    set16(b, h.extensions_len, static_cast<std::uint16_t>(b.size() - ext_start));
  }

  const std::size_t body_len = b.size() - body_start;
  b[h.handshake_len] = static_cast<std::uint8_t>(body_len >> 16);
  set16(b, h.handshake_len + 1, static_cast<std::uint16_t>(body_len));
  set16(b, h.record_len, static_cast<std::uint16_t>(b.size() - 5));
  return h;
}

}  // namespace dpi::test
