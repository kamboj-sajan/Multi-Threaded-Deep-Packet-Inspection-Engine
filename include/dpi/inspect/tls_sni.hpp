#pragma once

#include <string>

#include "dpi/common/bytes.hpp"

namespace dpi {

enum class SniStatus : std::uint8_t {
  Found,           // `sni` holds the canonical host name.
  NoSni,           // A valid ClientHello without a server_name extension.
  NotClientHello,  // Not a TLS handshake record carrying a ClientHello.
  Incomplete,      // Looks like a ClientHello but the record is not all here
                   // yet (e.g. split across TCP segments): retry with more.
  Malformed,       // A complete record whose lengths do not add up.
};

const char* to_string(SniStatus status) noexcept;

struct SniResult {
  SniStatus status = SniStatus::NotClientHello;
  std::string sni;
};

// Extracts the server name from a TLS ClientHello at the start of `payload`
// (the client's first bytes on a TCP connection). Walks, in order: record
// header (type 0x16), handshake header (type 0x01), version and random,
// session_id, cipher_suites, compression_methods, then the extensions until
// server_name (type 0), taking the first host_name (type 0) entry. Every
// length is checked against the bytes that remain at its level.
//
// Limitations: a ClientHello fragmented over several TLS records is
// reported as Malformed (very rare); with TLS 1.3 Encrypted Client Hello
// the visible SNI is only the public "outer" name.
SniResult parse_tls_client_hello(ByteView payload);

}  // namespace dpi
