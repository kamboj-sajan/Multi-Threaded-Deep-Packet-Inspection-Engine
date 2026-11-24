# Multi-threaded Deep Packet Inspection Engine

A C++20 traffic-analysis engine. It reads a PCAP capture, parses
Ethernet / IPv4 / TCP / UDP by hand, tracks bidirectional flows by 5-tuple,
extracts the TLS ClientHello SNI and HTTP Host to classify traffic, applies
blocking rules, writes the allowed packets to a new PCAP, and prints a
statistics report.

![Terminal demo: blocking rules, SNI classification, a 4x4 thread run and the test suite](docs/demo.gif)

<sub>Recorded with [vhs](https://github.com/charmbracelet/vhs) from
[tools/demo/demo.tape](tools/demo/demo.tape); re-record with `vhs tools/demo/demo.tape`.</sub>

The work is split into concurrent stages: a reader, N load-balancer
threads, K fast-path threads per load balancer, and a writer. They are
connected by bounded, thread-safe queues. Every packet of a flow, in both
directions, is handled by the same fast-path thread, so flow state needs no
locks.

* No third-party code apart from GoogleTest. PCAP, Ethernet, VLAN, IPv4,
  TCP, UDP, TLS and HTTP parsing are all written from scratch on
  `std::span`, `memcpy` and `ntohs`/`ntohl`.
* Built with `-Wall -Wextra -Wpedantic -Werror`. All 222 tests pass in Debug
  and Release with GCC 13, Clang 18 (Linux) and Apple Clang 21 (macOS), and
  under AddressSanitizer + UndefinedBehaviorSanitizer and ThreadSanitizer
  with Clang 18 and Apple Clang 21.
* Each layer is its own CMake library with its own test executable.

## Architecture

```
                     h = flow_hash(normalized 5-tuple)
                                   |
 input.pcap --> [ Reader ] ---+---> [ LB 0 ] ---+---> [ FP 0.0 ] ---+
                1 thread      |     h % N       +---> [ FP 0.1 ] ---+
                read record,  |                 |   (h / N) % K     |
                peek 5-tuple, +---> [ LB 1 ] ---+---> [ FP 1.0 ] ---+---> [ Writer ] --> output.pcap
                hash          |    full L2-L4   +---> [ FP 1.1 ] ---+     1 thread
                              |    decode,           flow table,
                              ...  drop malformed    TCP state, SNI / Host,
                                                     classify, rules, verdict

      every arrow is a BoundedBlockingQueue (mutex + 2 condition variables),
      carrying batches of up to 64 packets
```

| Stage | Threads | Responsibility | Code |
|---|---|---|---|
| Reader | 1 | read PCAP records, cheap 5-tuple peek, direction-independent hash, route to `LB[h % N]` | [`ReaderStage`](src/pipeline/stages.cpp) |
| Load balancer | N | full L2-L4 decode into `ParsedPacket`, count/drop malformed, route to `FP[(h / N) % K]` of its own group | [`LoadBalancerStage`](src/pipeline/stages.cpp) |
| Fast path | N x K | exclusive flow table, TCP state, SNI/Host on the first payload packets, classification, rules, verdict | [`FastPathStage`](src/pipeline/stages.cpp), [`FlowInspector`](src/pipeline/flow_inspector.cpp) |
| Writer | 1 | write forwarded packets | [`WriterStage`](src/pipeline/stages.cpp) |

**Flow affinity.** A packet's route is a function of its flow hash only, so
both directions of a flow go through the same LB and FP, and per-flow order
is preserved through the FIFO queues. **The order across different flows
can change** in the output, because FPs run in parallel. The determinism
tests check that the threaded pipeline gives exactly the same results as a
single-threaded run in every layout. See [DESIGN.md](DESIGN.md).

## Build and test

Requirements: CMake 3.25+, Ninja, and GCC 11+ or Clang 14+ (Apple Clang
works too). GoogleTest is fetched automatically, pinned by checksum.

```sh
cmake --preset debug && cmake --build --preset debug && ctest --preset debug
```

| Preset | Purpose |
|---|---|
| `debug` | development build with assertions |
| `release` | `-O3`, also builds the benchmark |
| `asan-ubsan` | AddressSanitizer + UndefinedBehaviorSanitizer; any UB report fails the run |
| `tsan` | ThreadSanitizer |
| `fuzz` | libFuzzer targets for the packet parser and SNI/Host extraction (Linux Clang) |

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs GCC and Clang
in Debug and Release, Clang with ASan+UBSan and with TSan, and a 60-second
libFuzzer smoke test per target. The same Linux environment runs locally
with Docker:

```sh
docker build -t dpi-dev tools/docker
docker run --rm -v "$PWD":/src -w /src dpi-dev tools/docker/ci_local.sh debug tsan
```

## Usage

```
dpi_engine <input.pcap> <output.pcap> [options]

  --rules <file>       blocking rules, e.g. rules/example_rules.txt
  --lbs <n>            load-balancer threads (default 2)
  --fps-per-lb <n>     fast-path threads per load balancer (default 2)
  --queue-size <n>     packets each inter-thread queue holds (default 4096)
  --batch-size <n>     packets handed between threads at once (default 64)
  --sequential         run every stage on one thread (correctness baseline)
  --report <file>      also write the report as JSON
```

Rules ([rules/example_rules.txt](rules/example_rules.txt)):

```
block ip 192.168.1.50        # either endpoint; CIDR such as 10.0.0.0/8 also works
block domain *.tiktok.com    # the name and all its subdomains (exact names also work)
block app YouTube            # the classified application
block port 6881              # either endpoint's port
```

Verdicts are per flow. A flow matching an ip, port or port-based app rule is
dropped from its first packet. A flow matching an app or domain rule is
dropped from the packet that revealed its SNI or Host. Packets before that,
typically the TCP handshake, are forwarded.

### Sample output

`build/release/src/app/dpi_engine tests/data/mixed.pcap out.pcap --rules rules/example_rules.txt`
(abridged):

```
Loaded 4 rules from rules/example_rules.txt
=== DPI engine report ===
Packets
  total                 254
  forwarded             185   72.8%
  dropped                59   23.2%
  malformed              10    3.9%
    truncated_ethernet           1
    bad_ip_header_length         1
    bad_tcp_data_offset          1
    ...
  non-IP (fwd)            2
Flows
  total                  30
  blocked                 7
    by ip                         2
    by port                       1
    by app                        3
    by domain                     1
Threads (2 LB x 2 FP)
  reader                254
  lb 0                 156   61.4%
  lb 1                  98   38.6%
  fp 0.0                69   28.3%
  fp 0.1                77   31.6%
  fp 1.0                71   29.1%
  fp 1.1                27   11.1%
  writer                185
Applications (flows / packets / bytes)
  Unknown           10          38          7851
  YouTube            3          36          4253
  HTTPS              3          34          4432
  Facebook           2          24          2831
  ...
Top SNIs / HTTP hosts (flows)
   1. www.netflix.com                              2
   2. www.youtube.com                              2
   3. api.github.com                               1
   ...
Performance
  ...
```

With only 30 flows the thread shares are uneven. On the 1000-flow capture,
each of 8 FPs gets between 11.6% and 13.5% of packets.
`--report report.json` writes the same data as JSON.

## Tests and test data

`ctest` runs 222 tests. Each library has its own unit tests on hand-built
byte arrays. They cover truncation at every header boundary, bad IHL and
TCP data offset, VLAN, IP fragments, a real OpenSSL ClientHello, ClientHellos
with no SNI or 600 extensions or corrupted lengths, flow keys and eviction,
and an MPMC queue stress test. Integration tests cover the full pipeline on
`tests/data/*.pcap`, the CLI, and a check that `tcpdump -r` reads the output.

The captures come from [tools/gen_pcap.py](tools/gen_pcap.py) (scapy,
fixed seeds, byte-identical on every run):

| Capture | Contents |
|---|---|
| `mixed.pcap` | HTTPS to known SNIs, HTTP, DNS, UDP noise, ICMP, ARP, VLAN, IP fragments, a blocked IP, BitTorrent, a snaplen-cut packet, one packet of every malformation |
| `malformed.pcap` | every malformation and a truncated final record |
| `many_flows.pcap` | 1000 interleaved flows, for comparing thread layouts |
| `tls_split.pcap` | ClientHellos split across 2 and 3 TCP segments, one out of order, and a split HTTP request |

The generator also computes the **expected** counts, classifications and
rule verdicts (with its own Python model of the rules) into
[tests/data/MANIFEST.md](tests/data/MANIFEST.md). The integration tests
assert those numbers, so the expectations never come from the engine's own
output.

## Benchmark

All numbers below were measured. Raw output is in
[bench/RESULTS.md](bench/RESULTS.md).

**Setup**

* **Capture.** `python3 tools/gen_bench_pcap.py` builds a 1,008,000-packet
  capture: 24,000 flows, 424.5 MB, 405-byte average frame. Each HTTPS flow
  has 50 packets: handshake, a ClientHello with an SNI, 20 data segments
  each ACKed, and teardown. There is also some DNS, and about 1000 flows are
  open at once.
* **Measurement.** The capture is **loaded into memory before timing** and
  the output goes to a null sink, so disk I/O is excluded. Each layout runs
  one warm-up plus 7 timed runs, and the tables show the median and the
  min-max spread. The harness fails if any layout forwards a different
  number of packets.
* **Machine.** Apple M2 (4 performance + 4 efficiency cores), 8 GB RAM,
  macOS 27.0.1, Apple clang 21, CMake Release (`-O3`). It is a working
  laptop: background desktop apps kept about 1-1.5 cores busy (76-86% idle
  before the runs).

```sh
python3 tools/gen_bench_pcap.py
cmake --preset release && cmake --build --preset release
build/release/bench/bench_pipeline bench/data/bench.pcap --repeats 7
```

**Throughput by fast-path thread count** (batch size 64, no rules):

| FP threads | Layout | Threads total | Mpps | Gbps | Mpps min-max |
|---:|---|---:|---:|---:|---:|
| - | sequential baseline | 1 | 6.79 | 21.99 | 5.85-7.13 |
| 1 | 1 LB x 1 FP | 4 | 9.48 | 30.73 | 9.32-10.03 |
| 2 | 1 LB x 2 FP | 5 | 10.53 | 34.12 | 6.84-10.71 |
| 4 | 2 LB x 2 FP | 8 | 9.74 | 31.56 | 9.36-9.85 |
| 4 | 1 LB x 4 FP | 7 | **11.35** | **36.80** | 10.07-11.42 |
| 8 | 2 LB x 4 FP | 12 | 7.10 | 23.01 | 5.61-7.53 |
| 8 | 4 LB x 2 FP | 14 | 8.70 | 28.20 | 7.64-8.75 |

The reader stage alone (read, copy into a `Packet`, peek, hash, nothing
downstream) runs at **13.61 Mpps**.

**With `rules/example_rules.txt`** (18.7% of packets dropped, 4,002 of
24,000 flows blocked), throughput barely changes. Median Mpps for 1 / 2 / 4 / 8 FP threads is 9.36 / 10.28 /
9.27 (2x2) and 10.28 (1x4) / 7.61 (2x4) and 8.05 (4x2), against 6.86
sequential.

**Per-packet hand-off** (`--batch-size 1`, no rules) is how the first version
worked:

| FP threads | 1 | 2 | 4 (2x2 / 1x4) | 8 (2x4 / 4x2) | sequential |
|---|---:|---:|---:|---:|---:|
| Mpps | 2.52 | 2.01 | 1.04 / 1.41 | 0.60 / 0.55 | 6.92 |

**What the numbers show**

1. **Batching decides whether threads help at all.** One packet costs about
   147 ns of work in total (6.8 Mpps sequential). Handing it to another
   thread through a mutex and condition-variable wake-up costs more than
   that. Without batching, every threaded layout was slower than one
   thread, and adding threads made it worse. With batches of 64, one lock
   and one wake-up cover 64 packets, and the pipeline overtakes the
   baseline.
2. **The single reader is the ceiling.** The best layout reaches 11.35 Mpps,
   1.67x the sequential baseline and 83% of what the reader thread can
   produce alone. Beyond 2-4 fast-path threads, more FPs cannot help
   (Amdahl's law). Reading a PCAP is sequential. At real line rate, NIC RSS
   queues would give each core its own reader.
3. **Oversubscription hurts.** The 8-FP layouts need 12-14 threads on 8
   cores, half of them efficiency cores, so threads compete for CPUs and
   throughput falls below the 4-FP layouts. Note that 1x4 (7 threads) beats
   2x2 (8 threads).
4. **Inspection and rules are cheap,** because only a flow's first payload
   packets are parsed. Every later packet takes the fast path.
5. **Gbps here means bytes processed from memory,** not traffic on a
   network interface. It is a measure of engine cost, not a line-rate
   claim.

Possible next steps, roughly by expected gain: recycle packet buffers from
a pool instead of allocating and zero-filling one per packet in the reader;
pin threads to performance cores on Linux; replace the mutex queues into
each LB and FP, which have a single producer, with lock-free SPSC rings.

## Limitations

* **IPv4 only.** IPv6 frames are counted as non-IP and forwarded without
  inspection.
* **One 802.1Q tag.** Double-tagged (QinQ) frames are treated as non-IP.
* **Minimal TCP reassembly.** A ClientHello or HTTP request split across
  segments is reassembled only if the segments arrive in order (up to
  16 KiB). Reordering, loss or a snaplen cut fall back to port-based
  classification.
* **TLS 1.3 Encrypted Client Hello** hides the real SNI. Only the outer,
  public name is visible.
* **QUIC / HTTP/3** payloads are encrypted, so UDP 443 is labelled `QUIC`
  by port only. **DNS query names** are not parsed, so `block domain` does
  not stop DNS lookups.
* **Handshake packets before the SNI is known are forwarded** to flows that
  are later blocked by app or domain rules.
* **IP fragments:** only the first fragment carries ports. Later fragments
  are tracked under a port-less key and are matched by ip rules only.
* **Hash routing balances flows, not bytes.** An elephant flow loads one FP.
* **Rules load once.** There is no hot reload.

[DESIGN.md](DESIGN.md) explains these choices, and
[INTERVIEW_NOTES.md](INTERVIEW_NOTES.md) walks through the code as 20
questions and answers.

## Repository layout

```
include/dpi/      public headers, one directory per library
src/              common, pcap_io, parser, flow, inspect, classifier,
                  rules, concurrency, pipeline, app (the CLI)
tests/            one test directory per library, plus integration/ and data/
fuzz/             libFuzzer targets and seed corpora
bench/            pipeline throughput benchmark
tools/            capture generators, ClientHello capture, Docker CI environment
rules/            example rules
```
