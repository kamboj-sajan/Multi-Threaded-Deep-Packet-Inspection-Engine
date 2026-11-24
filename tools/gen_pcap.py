#!/usr/bin/env python3
"""Generates the deterministic test captures in tests/data/.

Usage (from the repository root):
    python3 -m venv tools/.venv && tools/.venv/bin/pip install -r tools/requirements.txt
    tools/.venv/bin/python tools/gen_pcap.py

Every byte is derived from a fixed seed, so re-running the script
reproduces the committed files exactly. Expected counts are computed here,
from what was generated, and written to tests/data/MANIFEST.md; the
integration tests assert those numbers. They never come from the engine's
own output.

Captures:
  mixed.pcap       HTTPS to known SNIs, HTTP, DNS, UDP noise, ICMP, ARP,
                   VLAN, IP fragments, a blocked IP, BitTorrent, a
                   snaplen-truncated packet and one malformed packet of
                   every kind.
  malformed.pcap   Two valid packets, every malformed kind, and a final
                   record cut short.
  many_flows.pcap  1000 interleaved flows, used to compare thread layouts.
  tls_split.pcap   ClientHellos and an HTTP request split across TCP
                   segments (in order, and one out of order).
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import random
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP, fragment
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.packet import Raw

# scapy auto-dissects port-443 payloads as TLS while re-reading frames and
# warns about the synthetic (random) server records; those are expected.
logging.getLogger("scapy").setLevel(logging.ERROR)

BASE_TIME_US = 1_700_000_000 * 1_000_000
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"


# --------------------------------------------------------------------------
# Capture model
# --------------------------------------------------------------------------

@dataclass
class Frame:
    data: bytes
    label: str = "ok"           # "ok", "non_ip" or a malformed reason
    orig_len: int | None = None  # None = same as len(data)
    key: tuple | None = None     # normalised 5-tuple for "ok" IPv4 frames


@dataclass
class FlowSpec:
    """One flow's frames (kept in order) plus what the engine should conclude."""
    frames: list[Frame]
    sni: str | None = None       # expected SNI / HTTP Host
    app: str | None = None       # expected application name
    note: str = ""


@dataclass
class Capture:
    name: str
    flows: list[FlowSpec] = field(default_factory=list)
    truncated_tail: bool = False


def normalised_key(pkt) -> tuple | None:
    """Mirrors the engine's normalisation: smaller (ip, port) endpoint first.

    The packet is re-dissected from its bytes first, because objects built
    by scapy (e.g. by fragment()) do not always carry the layers the bytes
    on the wire actually contain.
    """
    pkt = Ether(bytes(pkt))
    if IP not in pkt:
        return None
    ip = pkt[IP]
    sport = dport = 0
    if ip.frag == 0 and (TCP in pkt or UDP in pkt):
        l4 = pkt[TCP] if TCP in pkt else pkt[UDP]
        sport, dport = l4.sport, l4.dport
    a = (int(ipaddress.IPv4Address(ip.src)), sport)
    b = (int(ipaddress.IPv4Address(ip.dst)), dport)
    lo, hi = (a, b) if a <= b else (b, a)
    return (lo, hi, ip.proto)


def frame(pkt, label="ok", orig_len=None) -> Frame:
    return Frame(bytes(pkt), label, orig_len, normalised_key(pkt) if label == "ok" else None)


# --------------------------------------------------------------------------
# Protocol payloads
# --------------------------------------------------------------------------

def tls_ext(ext_type: int, body: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(body)) + body


def client_hello(rng: random.Random, sni: str | None, extra_extensions: int = 0,
                 padding: int = 0, sni_last: bool = False) -> bytes:
    """A TLS 1.3-capable ClientHello laid out like a current browser's.

    `padding` adds a padding extension (as browsers do, RFC 7685) and
    `sni_last` moves server_name to the end, so that in a hello larger than
    one TCP segment the SNI lands in a later segment (browsers randomise
    extension order, so this happens in real traffic).
    """
    def server_name_ext() -> bytes:
        name = sni.encode()
        entry = struct.pack("!BH", 0, len(name)) + name
        return tls_ext(0x0000, struct.pack("!H", len(entry)) + entry)

    exts = [tls_ext(0x0A0A, b"")]  # GREASE
    if sni is not None and not sni_last:
        exts.append(server_name_ext())
    exts.append(tls_ext(0x0017, b""))                      # extended_master_secret
    exts.append(tls_ext(0xFF01, b"\x00"))                  # renegotiation_info
    groups = [0x1A1A, 0x001D, 0x0017, 0x0018]
    exts.append(tls_ext(0x000A, struct.pack("!H", 2 * len(groups)) +
                        b"".join(struct.pack("!H", g) for g in groups)))
    exts.append(tls_ext(0x000B, b"\x01\x00"))              # ec_point_formats
    exts.append(tls_ext(0x0023, b""))                      # session_ticket
    alpn = b"".join(bytes([len(p)]) + p for p in (b"h2", b"http/1.1"))
    exts.append(tls_ext(0x0010, struct.pack("!H", len(alpn)) + alpn))
    exts.append(tls_ext(0x0005, b"\x01\x00\x00\x00\x00"))  # status_request
    sigalgs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    exts.append(tls_ext(0x000D, struct.pack("!H", 2 * len(sigalgs)) +
                        b"".join(struct.pack("!H", s) for s in sigalgs)))
    exts.append(tls_ext(0x0012, b""))                      # signed_certificate_timestamp
    key_share = struct.pack("!HH", 0x001D, 32) + rng.randbytes(32)
    exts.append(tls_ext(0x0033, struct.pack("!H", len(key_share)) + key_share))
    exts.append(tls_ext(0x002D, b"\x01\x01"))              # psk_key_exchange_modes
    exts.append(tls_ext(0x002B, b"\x04\x03\x04\x03\x03"))  # supported_versions 1.3, 1.2
    exts.append(tls_ext(0x001B, b"\x02\x00\x02"))          # compress_certificate
    for i in range(extra_extensions):                      # private-use filler
        exts.append(tls_ext(0xFE00 + i, rng.randbytes(4)))
    if padding:
        exts.append(tls_ext(0x0015, b"\x00" * padding))     # padding
    if sni is not None and sni_last:
        exts.append(server_name_ext())
    exts.append(tls_ext(0x1A1A, b"\x00"))                  # GREASE
    ext_bytes = b"".join(exts)

    ciphers = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
               0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
    body = (b"\x03\x03" + rng.randbytes(32) +             # legacy_version, random
            b"\x20" + rng.randbytes(32) +                  # session_id
            struct.pack("!H", 2 * len(ciphers)) +
            b"".join(struct.pack("!H", c) for c in ciphers) +
            b"\x01\x00" +                                  # compression: null
            struct.pack("!H", len(ext_bytes)) + ext_bytes)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def check_client_hello(record: bytes, sni: str | None) -> None:
    """Independent check: scapy's TLS dissector must find the same SNI."""
    from scapy.layers.tls.record import TLS
    from scapy.layers.tls.extensions import TLS_Ext_ServerName

    parsed = TLS(record)
    hello = parsed.msg[0]
    names = [s.servername.decode()
             for e in (hello.ext or []) if isinstance(e, TLS_Ext_ServerName)
             for s in e.servernames]
    assert names == ([sni] if sni else []), (names, sni)


def server_tls_bytes(rng: random.Random, n: int) -> bytes:
    """Opaque server-side TLS records (ServerHello-shaped, then app data)."""
    hello = b"\x16\x03\x03" + struct.pack("!H", 90) + b"\x02" + rng.randbytes(89)
    data = b"\x17\x03\x03" + struct.pack("!H", n) + rng.randbytes(n)
    return hello + data


# --------------------------------------------------------------------------
# Flow builders
# --------------------------------------------------------------------------

class Builder:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.ip_id = 1

    def _next_id(self) -> int:
        self.ip_id = (self.ip_id + 1) & 0xFFFF
        return self.ip_id

    def _l2(self, from_client: bool, vlan: int | None):
        eth = Ether(src=CLIENT_MAC if from_client else SERVER_MAC,
                    dst=SERVER_MAC if from_client else CLIENT_MAC)
        return eth / Dot1Q(vlan=vlan) if vlan is not None else eth

    def tcp_session(self, cip, sip, cport, sport, exchanges, vlan=None, close="fin",
                    truncate_last_server_payload=False) -> list[Frame]:
        """Handshake, request/response exchanges, then FIN or RST teardown."""
        cseq = self.rng.randrange(1 << 32)
        sseq = self.rng.randrange(1 << 32)
        frames: list[Frame] = []

        def seg(from_client, flags, payload=b""):
            nonlocal cseq, sseq
            src, dst = (cip, sip) if from_client else (sip, cip)
            sp, dp = (cport, sport) if from_client else (sport, cport)
            seq, ack = (cseq, sseq) if from_client else (sseq, cseq)
            pkt = (self._l2(from_client, vlan) / IP(src=src, dst=dst, id=self._next_id()) /
                   TCP(sport=sp, dport=dp, flags=flags, seq=seq, ack=ack if "A" in flags else 0,
                       window=64240))
            if payload:
                pkt = pkt / Raw(payload)
            advance = len(payload) + (1 if ("S" in flags or "F" in flags) else 0)
            if from_client:
                cseq = (cseq + advance) % (1 << 32)
            else:
                sseq = (sseq + advance) % (1 << 32)
            return pkt

        frames.append(frame(seg(True, "S")))
        frames.append(frame(seg(False, "SA")))
        frames.append(frame(seg(True, "A")))
        last_server = max((i for i, (fc, _) in enumerate(exchanges) if not fc), default=-1)
        for i, (from_client, payload) in enumerate(exchanges):
            pkt = seg(from_client, "PA", payload)
            if truncate_last_server_payload and i == last_server:
                # Simulates a snaplen cut: 50 bytes missing, origlen intact.
                data = bytes(pkt)
                frames.append(Frame(data[:-50], "ok", len(data), normalised_key(pkt)))
            else:
                frames.append(frame(pkt))
            frames.append(frame(seg(not from_client, "A")))
        if close == "fin":
            frames.append(frame(seg(True, "FA")))
            frames.append(frame(seg(False, "FA")))
            frames.append(frame(seg(True, "A")))
        elif close == "rst":
            frames.append(frame(seg(False, "RA")))
        return frames

    def https(self, cip, sip, cport, sni, app, vlan=None, extra_extensions=0, **kw) -> FlowSpec:
        hello = client_hello(self.rng, sni, extra_extensions)
        check_client_hello(hello, sni)
        exchanges = [(True, hello), (False, server_tls_bytes(self.rng, 300)),
                     (True, b"\x17\x03\x03\x00\x40" + self.rng.randbytes(64))]
        return FlowSpec(self.tcp_session(cip, sip, cport, 443, exchanges, vlan=vlan, **kw),
                        sni=sni, app=app, note="HTTPS")

    def split_https(self, cip, sip, cport, sni, app, segments, reorder=False) -> FlowSpec:
        """HTTPS whose ClientHello (1.9 KB, SNI at the end) spans `segments`
        TCP segments. With `reorder`, the second segment arrives first."""
        hello = client_hello(self.rng, sni, padding=1600, sni_last=True)
        check_client_hello(hello, sni)
        size = -(-len(hello) // segments)  # ceiling division
        exchanges = [(True, hello[i:i + size]) for i in range(0, len(hello), size)]
        exchanges.append((False, server_tls_bytes(self.rng, 300)))
        frames = self.tcp_session(cip, sip, cport, 443, exchanges)
        note = f"ClientHello in {segments} segments"
        if reorder:
            # Frames: SYN, SYN-ACK, ACK, then (data, ack) per exchange.
            frames[3], frames[5] = frames[5], frames[3]
            note += ", second segment first"
        return FlowSpec(frames, sni=None if reorder else sni, app=app, note=note)

    def split_http(self, cip, sip, cport, host, app) -> FlowSpec:
        """HTTP request whose Host header is in the second TCP segment."""
        first = b"GET /index.html HTTP/1.1\r\nUser-Agent: dpi-test/1.0\r\nAccept: */*\r\n"
        second = f"Host: {host}\r\n\r\n".encode()
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        frames = self.tcp_session(cip, sip, cport, 80, [(True, first), (True, second), (False, response)])
        return FlowSpec(frames, sni=host, app=app, note="HTTP request in 2 segments")

    def http(self, cip, sip, cport, host, app) -> FlowSpec:
        request = (f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: dpi-test/1.0\r\n"
                   f"Accept: */*\r\n\r\n").encode()
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        frames = self.tcp_session(cip, sip, cport, 80, [(True, request), (False, response)])
        return FlowSpec(frames, sni=host, app=app, note="HTTP")

    def dns(self, cip, sip, cport, qname) -> FlowSpec:
        txid = self.rng.randrange(1 << 16)
        q = (self._l2(True, None) / IP(src=cip, dst=sip, id=self._next_id()) /
             UDP(sport=cport, dport=53) / DNS(id=txid, rd=1, qd=DNSQR(qname=qname)))
        r = (self._l2(False, None) / IP(src=sip, dst=cip, id=self._next_id()) /
             UDP(sport=53, dport=cport) /
             DNS(id=txid, qr=1, rd=1, ra=1, qd=DNSQR(qname=qname),
                 an=DNSRR(rrname=qname, ttl=300, rdata="198.51.100.7")))
        return FlowSpec([frame(q), frame(r)], app="DNS", note=f"DNS {qname}")

    def udp_noise(self, cip, sip, cport, sport, packets) -> FlowSpec:
        frames = []
        for i in range(packets):
            from_client = i % 2 == 0
            src, dst = (cip, sip) if from_client else (sip, cip)
            sp, dp = (cport, sport) if from_client else (sport, cport)
            pkt = (self._l2(from_client, None) / IP(src=src, dst=dst, id=self._next_id()) /
                   UDP(sport=sp, dport=dp) / Raw(self.rng.randbytes(self.rng.randrange(20, 200))))
            frames.append(frame(pkt))
        return FlowSpec(frames, app="Unknown", note="UDP noise")

    def icmp_echo(self, cip, sip) -> FlowSpec:
        req = self._l2(True, None) / IP(src=cip, dst=sip, id=self._next_id()) / ICMP(type=8, id=7, seq=1) / Raw(b"ping" * 8)
        rep = self._l2(False, None) / IP(src=sip, dst=cip, id=self._next_id()) / ICMP(type=0, id=7, seq=1) / Raw(b"ping" * 8)
        return FlowSpec([frame(req), frame(rep)], app="Unknown", note="ICMP echo")

    def arp(self) -> FlowSpec:
        pkt = Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(psrc="10.0.0.1", pdst="10.0.0.254")
        return FlowSpec([frame(pkt, label="non_ip")], note="ARP (non-IP)")

    def fragmented_udp(self, cip, sip) -> FlowSpec:
        whole = IP(src=cip, dst=sip, id=0x4242) / UDP(sport=33333, dport=5000) / Raw(self.rng.randbytes(3000))
        frags = fragment(whole, fragsize=1480)
        frames = [frame(self._l2(True, None) / f) for f in frags]
        # Two engine flows: only the first fragment carries the UDP ports,
        # later fragments are tracked under a port-less (ports 0) key.
        return FlowSpec(frames, app="Unknown",
                        note=f"UDP datagram in {len(frags)} IP fragments (2 flows)")

    def malformed(self) -> list[FlowSpec]:
        """One packet per malformation, each standalone and caplen == wire length."""
        eth = Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        good_ip = dict(src="10.9.9.1", dst="10.9.9.2")
        specs = []

        def add(label, data):
            specs.append(FlowSpec([Frame(bytes(data), label)], note=f"malformed: {label}"))

        add("truncated_ethernet", bytes(eth)[:10])
        add("truncated_vlan", bytes(eth / Dot1Q(vlan=5))[:16])
        add("truncated_ipv4", bytes(eth / IP(**good_ip) / TCP())[:14 + 12])
        add("bad_ip_version", eth / IP(version=6, **good_ip) / TCP())
        add("bad_ip_header_length", eth / IP(ihl=4, **good_ip) / TCP())
        add("bad_ip_total_length", eth / IP(len=10, **good_ip) / TCP())
        # IP payload of 10 bytes: too small for a 20-byte TCP header.
        add("truncated_tcp", bytes(eth / IP(len=30, proto=6, **good_ip) / Raw(bytes(TCP())[:10])))
        add("bad_tcp_data_offset", eth / IP(**good_ip) / TCP(dataofs=2) / Raw(b"x" * 8))
        add("truncated_udp", bytes(eth / IP(len=24, proto=17, **good_ip) / Raw(b"\x00\x35\x00\x35")))
        add("bad_udp_length", eth / IP(**good_ip) / UDP(len=3) / Raw(b"abc"))
        return specs


# --------------------------------------------------------------------------
# Capture definitions
# --------------------------------------------------------------------------

def mixed_capture() -> Capture:
    b = Builder(seed=1)
    c = Capture("mixed.pcap")
    client = "192.168.1.10"
    add = c.flows.append

    add(b.https(client, "142.250.72.14", 50001, "www.youtube.com", "YouTube"))
    add(b.https(client, "142.250.72.14", 50002, "www.youtube.com", "YouTube"))
    add(b.https(client, "173.194.55.6", 50003, "r4---sn-ab5l6nzr.googlevideo.com", "YouTube"))
    add(b.https(client, "52.89.124.203", 50004, "www.netflix.com", "Netflix"))
    add(b.https(client, "157.240.22.35", 50005, "www.facebook.com", "Facebook"))
    add(b.https(client, "157.240.22.19", 50006, "scontent.xx.fbcdn.net", "Facebook"))
    add(b.https(client, "157.240.22.174", 50007, "www.instagram.com", "Instagram"))
    add(b.https(client, "157.240.22.53", 50008, "web.whatsapp.com", "WhatsApp"))
    add(b.https(client, "142.250.72.4", 50009, "www.google.com", "Google"))
    add(b.https(client, "140.82.112.3", 50010, "github.com", "GitHub", truncate_last_server_payload=True))
    add(b.https(client, "140.82.112.5", 50011, "api.github.com", "GitHub", vlan=100))
    add(b.https(client, "23.40.44.10", 50012, "www.tiktok.com", "TikTok"))
    add(b.https(client, "203.0.113.10", 50013, None, "HTTPS"))
    add(b.https(client, "203.0.113.20", 50014, "many-extensions.example.net", "HTTPS",
                extra_extensions=40))
    add(b.https("192.168.1.50", "93.184.215.14", 50015, "example.org", "HTTPS",
                close="rst"))
    add(b.http(client, "93.184.215.14", 50016, "example.com", "HTTP"))
    add(b.http(client, "52.89.124.203", 50017, "www.netflix.com", "Netflix"))
    add(b.dns(client, "8.8.8.8", 53001, "www.youtube.com"))
    add(b.dns(client, "8.8.8.8", 53002, "github.com"))
    add(b.dns(client, "1.1.1.1", 53003, "www.tiktok.com"))
    for i in range(5):
        add(b.udp_noise(client, f"198.51.100.{20 + i}", 40000 + i, 9000 + i, 2 + i))
    add(b.udp_noise("192.168.1.50", "198.51.100.99", 41000, 9999, 3))
    add(bittorrent(b, client))
    add(b.icmp_echo(client, "8.8.4.4"))
    add(b.arp())
    add(b.arp())
    add(b.fragmented_udp(client, "10.0.0.53"))
    c.flows.extend(b.malformed())
    return c


def bittorrent(b: Builder, client: str) -> FlowSpec:
    handshake = b"\x13BitTorrent protocol" + b"\x00" * 8 + b.rng.randbytes(40)
    frames = b.tcp_session(client, "203.0.113.66", 51413, 6881,
                           [(True, handshake), (False, handshake)])
    return FlowSpec(frames, app="Unknown", note="BitTorrent on port 6881")


def malformed_capture() -> Capture:
    b = Builder(seed=2)
    c = Capture("malformed.pcap", truncated_tail=True)
    c.flows.append(b.udp_noise("10.1.1.1", "10.1.1.2", 4000, 4001, 2))
    c.flows.extend(b.malformed())
    return c


def tls_split_capture() -> Capture:
    b = Builder(seed=4)
    c = Capture("tls_split.pcap")
    client = "192.168.7.10"
    c.flows.append(b.split_https(client, "142.250.72.14", 51001, "www.youtube.com", "YouTube", 2))
    c.flows.append(b.split_https(client, "140.82.112.3", 51002, "github.com", "GitHub", 3))
    # Out of order: reassembly gives up, so only the port (443) is known.
    c.flows.append(b.split_https(client, "52.89.124.203", 51003, "www.netflix.com", "HTTPS", 2,
                                 reorder=True))
    c.flows.append(b.split_http(client, "52.89.124.203", 51004, "www.netflix.com", "Netflix"))
    return c


def many_flows_capture() -> Capture:
    b = Builder(seed=3)
    c = Capture("many_flows.pcap")
    snis = [("www.youtube.com", "YouTube"), ("i.ytimg.com", "YouTube"),
            ("www.netflix.com", "Netflix"), ("www.facebook.com", "Facebook"),
            ("www.instagram.com", "Instagram"), ("www.google.com", "Google"),
            ("github.com", "GitHub"), ("unknown-site.example", "HTTPS")]
    for i in range(1000):
        client = f"10.{20 + i % 8}.{(i // 8) % 250}.{1 + i % 200}"
        port = 20000 + i
        kind = i % 10
        if kind < 6:
            sni, app = snis[b.rng.randrange(len(snis))]
            c.flows.append(b.https(client, f"203.0.113.{1 + i % 50}", port, sni, app))
        elif kind < 8:
            c.flows.append(b.dns(client, "8.8.8.8", port, f"host{i}.example.com"))
        elif kind == 8:
            c.flows.append(b.http(client, "93.184.215.14", port, "example.com", "HTTP"))
        else:
            c.flows.append(b.udp_noise(client, "198.51.100.1", port, 7000, 4))
    return c


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def interleave(capture: Capture, seed: int) -> list[Frame]:
    """Mixes flows together while keeping each flow's own order."""
    rng = random.Random(seed)
    queues = [list(f.frames) for f in capture.flows]
    out = []
    active = [i for i, q in enumerate(queues) if q]
    while active:
        i = active[rng.randrange(len(active))]
        out.append(queues[i].pop(0))
        if not queues[i]:
            active.remove(i)
    return out


def write_pcap(path: Path, frames: list[Frame], truncated_tail: bool) -> None:
    with path.open("wb") as f:
        # Little-endian, microsecond magic, snaplen 65535, Ethernet.
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            ts = BASE_TIME_US + i * 1000  # 1 ms apart
            orig = fr.orig_len if fr.orig_len is not None else len(fr.data)
            f.write(struct.pack("<IIII", ts // 1_000_000, ts % 1_000_000, len(fr.data), orig))
            f.write(fr.data)
        if truncated_tail:
            # Header promises 100 bytes; only 30 follow.
            ts = BASE_TIME_US + len(frames) * 1000
            f.write(struct.pack("<IIII", ts // 1_000_000, ts % 1_000_000, 100, 100))
            f.write(b"\xAB" * 30)


def summarise(capture: Capture, frames: list[Frame]) -> list[str]:
    labels = Counter(fr.label for fr in frames)
    malformed = {k: v for k, v in labels.items() if k not in ("ok", "non_ip")}
    flows = {fr.key for fr in frames if fr.key is not None}
    truncated = 1 if capture.truncated_tail else 0
    lines = [f"## {capture.name}", "",
             f"- total records: {len(frames) + truncated}",
             f"- valid IPv4 packets: {labels['ok']}",
             f"- non-IP packets: {labels['non_ip']}",
             f"- malformed packets: {sum(malformed.values()) + truncated}"]
    for reason in sorted(malformed):
        lines.append(f"  - {reason}: {malformed[reason]}")
    if truncated:
        lines.append("  - truncated_record: 1")
    lines.append(f"- flows: {len(flows)}")
    lines.append(f"- snaplen-truncated packets (caplen < origlen): "
                 f"{sum(1 for fr in frames if fr.orig_len)}")

    # Count engine flows (distinct keys), since one generated exchange can
    # legitimately become two flows (IP fragments).
    per_app = Counter()
    for f in capture.flows:
        if f.app:
            per_app[f.app] += len({fr.key for fr in f.frames if fr.key is not None})
    lines += ["", "Expected classification (flows by app):", ""]
    for app, n in sorted(per_app.items()):
        lines.append(f"- {app}: {n}")
    snis = Counter(f.sni for f in capture.flows if f.sni)
    if len(capture.flows) <= 60:
        lines += ["", "Flows:", "", "| # | packets | SNI / Host | app | note |", "|---|---|---|---|---|"]
        for i, f in enumerate(capture.flows):
            lines.append(f"| {i} | {len(f.frames)} | {f.sni or ''} | {f.app or ''} | {f.note} |")
    else:
        lines += ["", "Flows by SNI / Host:", ""]
        for sni, n in sorted(snis.items()):
            lines.append(f"- {sni}: {n}")
    lines.append("")
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="tests/data", type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    manifest = ["# Test captures", "",
                "Generated by `tools/gen_pcap.py`. Do not edit by hand; re-run the script.",
                "Counts below are computed by the generator from what it built.", ""]
    for seed, capture in enumerate([mixed_capture(), malformed_capture(), many_flows_capture(),
                                     tls_split_capture()], 100):
        frames = interleave(capture, seed)
        write_pcap(args.out / capture.name, frames, capture.truncated_tail)
        manifest += summarise(capture, frames)
        print(f"wrote {args.out / capture.name}: {len(frames)} frames")
    (args.out / "MANIFEST.md").write_text("\n".join(manifest))


if __name__ == "__main__":
    main()
