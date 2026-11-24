#pragma once

#include <string>

#include "dpi/common/bytes.hpp"

namespace dpi {

enum class HttpHostStatus : std::uint8_t {
  Found,       // `host` holds the canonical host name (port removed).
  NoHost,      // A complete HTTP/1.x request header without a Host header.
  NotHttp,     // Does not start like an HTTP/1.x request.
  Incomplete,  // Starts like a request, but the headers are not all here.
};

const char* to_string(HttpHostStatus status) noexcept;

struct HttpHostResult {
  HttpHostStatus status = HttpHostStatus::NotHttp;
  std::string host;
};

// Extracts the Host header from an HTTP/1.x request at the start of
// `payload`. Detection is by request syntax ("GET / HTTP/1.1"), not port,
// so HTTP on 8080 is recognised too. Only the first 8 KiB are examined.
HttpHostResult parse_http_host(ByteView payload);

}  // namespace dpi
