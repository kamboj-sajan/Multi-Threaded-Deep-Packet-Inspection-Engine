#!/usr/bin/env python3
"""Generates a large, deterministic capture for benchmarking (>= 1M packets).

Usage (from the repository root):
    python3 tools/gen_bench_pcap.py                       # bench/data/bench.pcap
    python3 tools/gen_bench_pcap.py --flows 40000 --out /tmp/big.pcap

Unlike tools/gen_pcap.py this builds frames with struct directly (no
scapy), because scapy is far too slow for a million packets. The traffic
model is deliberately simple but shaped like real web traffic:

  * HTTPS flows of 50 packets: TCP handshake, a ClientHello with an SNI
    from a fixed list, a server "certificate" segment, 20 server data
    segments each ACKed by the client, then FIN/FIN/ACK. Only the first few
    packets are inspected; the rest exercise the fast path.
  * One DNS query/response pair for every 5 HTTPS flows.
  * About 1000 flows are open at any moment and their packets interleave,
    so every flow table holds many live flows.

Average frame size is about 400 bytes.
"""

from __future__ import annotations

import argparse
import random
import struct
from pathlib import Path

SNIS = ["www.youtube.com", "rr3---sn-q4f7s.googlevideo.com", "www.netflix.com", "www.facebook.com",
        "static.xx.fbcdn.net", "www.instagram.com", "web.whatsapp.com", "www.google.com", "github.com",
        "www.tiktok.com", "api.example.com", "cdn.example.net", "www.wikipedia.org", "news.example.org"]

ETH_HEADER = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01
DATA_SEGMENTS = 20
DATA_BYTES = 800
CONCURRENT_FLOWS = 1000


def ip_checksum(header: bytes) -> int:
    total = sum(struct.unpack("!10H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv4(src: int, dst: int, proto: int, payload: bytes, ident: int) -> bytes:
    header = struct.pack("!BBHHHBBHII", 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, src, dst)
    header = header[:10] + struct.pack("!H", ip_checksum(header)) + header[12:]
    return header + payload


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def client_hello(sni: str, rng: random.Random) -> bytes:
    name = sni.encode()
    entry = struct.pack("!BH", 0, len(name)) + name
    exts = struct.pack("!HH", 0, len(entry) + 2) + struct.pack("!H", len(entry)) + entry
    exts += struct.pack("!HH", 0x000A, 8) + b"\x00\x06\x00\x1d\x00\x17\x00\x18"
    exts += struct.pack("!HH", 0x0033, 38) + b"\x00\x24\x00\x1d\x00\x20" + rng.randbytes(32)
    exts += struct.pack("!HH", 0x002B, 5) + b"\x04\x03\x04\x03\x03"
    exts += struct.pack("!HH", 0x0015, 300) + bytes(300)  # padding, as browsers send
    ciphers = b"".join(struct.pack("!H", c) for c in (0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F))
    body = (b"\x03\x03" + rng.randbytes(32) + b"\x20" + rng.randbytes(32) +
            struct.pack("!H", len(ciphers)) + ciphers + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


class Flow:
    """Yields one flow's frames in order."""

    def __init__(self, index: int, rng: random.Random):
        self.rng = rng
        self.client = (10 << 24) | (index % 65000 + 1)          # 10.0.x.y
        self.server = (203 << 24) | (index % 251 + 1)           # 203.0.0.z
        self.cport = 20000 + index % 40000
        self.ident = index & 0xFFFF
        self.is_dns = index % 6 == 5
        self.sni = SNIS[index % len(SNIS)]
        self.frames = self._dns() if self.is_dns else self._https()

    def _frame(self, from_client: bool, proto: int, l4: bytes) -> bytes:
        self.ident = (self.ident + 1) & 0xFFFF
        src, dst = (self.client, self.server) if from_client else (self.server, self.client)
        return ETH_HEADER + ipv4(src, dst, proto, l4, self.ident)

    def _dns(self):
        query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01"
        yield self._frame(True, 17, udp(self.cport, 53, query))
        yield self._frame(False, 17, udp(53, self.cport, query + self.rng.randbytes(16)))

    def _https(self):
        c, s = self.rng.randrange(1 << 31), self.rng.randrange(1 << 31)
        cp, sp = self.cport, 443

        def seg(from_client, flags, payload=b""):
            nonlocal c, s
            if from_client:
                out = self._frame(True, 6, tcp(cp, sp, c, s, flags, payload))
                c += len(payload) + (1 if flags & (SYN | FIN) else 0)
            else:
                out = self._frame(False, 6, tcp(sp, cp, s, c, flags, payload))
                s += len(payload) + (1 if flags & (SYN | FIN) else 0)
            return out

        yield seg(True, SYN)
        yield seg(False, SYN | ACK)
        yield seg(True, ACK)
        yield seg(True, PSH | ACK, client_hello(self.sni, self.rng))
        yield seg(False, ACK)
        yield seg(False, PSH | ACK, b"\x16\x03\x03" + self.rng.randbytes(1200))
        yield seg(True, ACK)
        payload = self.rng.randbytes(DATA_BYTES)
        for _ in range(DATA_SEGMENTS):
            yield seg(False, PSH | ACK, payload)
            yield seg(True, ACK)
        yield seg(True, FIN | ACK)
        yield seg(False, FIN | ACK)
        yield seg(True, ACK)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--flows", type=int, default=24000, help="number of flows (default 24000)")
    parser.add_argument("--out", type=Path, default=Path("bench/data/bench.pcap"))
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)

    rng = random.Random(2024)
    next_flow = 0
    active: list[Flow] = []
    packets = 0
    ts_us = 1_700_000_000 * 1_000_000
    with args.out.open("wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        while next_flow < args.flows or active:
            while len(active) < CONCURRENT_FLOWS and next_flow < args.flows:
                active.append(Flow(next_flow, rng))
                next_flow += 1
            i = rng.randrange(len(active))
            frame = next(active[i].frames, None)
            if frame is None:
                active[i] = active[-1]
                active.pop()
                continue
            f.write(struct.pack("<IIII", ts_us // 1_000_000, ts_us % 1_000_000, len(frame), len(frame)))
            f.write(frame)
            packets += 1
            ts_us += 10
    print(f"wrote {args.out}: {packets} packets, {args.out.stat().st_size / 1e6:.1f} MB")


if __name__ == "__main__":
    main()
