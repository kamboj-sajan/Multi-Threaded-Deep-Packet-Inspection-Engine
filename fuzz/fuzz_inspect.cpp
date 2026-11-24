// libFuzzer target for payload inspection (TLS ClientHello SNI and HTTP
// Host). Any extracted name must be canonical: non-empty, lower case and
// free of characters a host name cannot contain.

#include <cstddef>
#include <cstdint>
#include <string>

#include "dpi/inspect/http_host.hpp"
#include "dpi/inspect/tls_sni.hpp"

namespace {

void check_canonical(const std::string& name) {
  if (name.empty() || name.size() > 253 || name.front() == '.') {
    __builtin_trap();
  }
  for (const char c : name) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
    if (!ok) {
      __builtin_trap();
    }
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const dpi::ByteView payload(data, size);
  const dpi::SniResult tls = dpi::parse_tls_client_hello(payload);
  if (tls.status == dpi::SniStatus::Found) {
    check_canonical(tls.sni);
  }
  const dpi::HttpHostResult http = dpi::parse_http_host(payload);
  if (http.status == dpi::HttpHostStatus::Found) {
    check_canonical(http.host);
  }
  return 0;
}
