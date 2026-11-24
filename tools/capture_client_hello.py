#!/usr/bin/env python3
"""Captures a real ClientHello from the local OpenSSL and writes it as a C++
test fixture (tests/inspect/fixtures/openssl_client_hello.hpp).

No network is involved: Python's ssl module drives OpenSSL through memory
BIOs, and the first flight of bytes it produces is the ClientHello. The
random, session id and key share differ on every run, so the committed
fixture is a one-off capture; re-running produces an equivalent hello.

Usage: python3 tools/capture_client_hello.py
"""

import ssl
from pathlib import Path

SNI = "www.example.com"
OUT = Path("tests/inspect/fixtures/openssl_client_hello.hpp")


def capture() -> bytes:
    ctx = ssl.create_default_context()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    conn = ctx.wrap_bio(incoming, outgoing, server_hostname=SNI)
    try:
        conn.do_handshake()
    except ssl.SSLWantReadError:
        pass  # expected: it is waiting for the ServerHello
    return outgoing.read()


def main() -> None:
    hello = capture()
    assert hello[0] == 0x16 and hello[5] == 0x01, "not a TLS ClientHello"
    rows = [", ".join(f"0x{b:02x}" for b in hello[i:i + 12]) for i in range(0, len(hello), 12)]
    body = ",\n    ".join(rows)
    OUT.write_text(f"""#pragma once

// A real TLS ClientHello captured from {ssl.OPENSSL_VERSION}
// by tools/capture_client_hello.py (SNI "{SNI}", {len(hello)} bytes).

#include <array>
#include <cstdint>

namespace dpi::test {{

inline constexpr const char* kOpensslHelloSni = "{SNI}";

inline constexpr std::array<std::uint8_t, {len(hello)}> kOpensslClientHello = {{
    {body},
}};

}}  // namespace dpi::test
""")
    print(f"wrote {OUT} ({len(hello)} bytes, {ssl.OPENSSL_VERSION})")


if __name__ == "__main__":
    main()
