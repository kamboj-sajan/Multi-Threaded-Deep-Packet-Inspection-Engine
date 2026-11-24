# Design

This document explains the main design decisions in the DPI engine and the
trade-offs behind them. For build instructions and results see the
[README](README.md); for a question-and-answer tour see
[INTERVIEW_NOTES.md](INTERVIEW_NOTES.md).

## 1. Pipeline and flow affinity

```
              h = flow_hash(normalized 5-tuple)
                          |
 PCAP --> [Reader] --+--> [LB 0] --+--> [FP 0.0] --+
          1 thread   |  h % N      +--> [FP 0.1] --+
                     |             |  (h / N) % K  |
                     +--> [LB 1] --+--> [FP 1.0] --+--> [Writer] --> PCAP
                     |             +--> [FP 1.1] --+    1 thread
                     ...  N LBs        N*K FPs
```

| Stage | Threads | Work | Code |
|---|---|---|---|
| Reader | 1 | read records, cheap 5-tuple peek, routing hash | `ReaderStage` in [src/pipeline/stages.cpp](src/pipeline/stages.cpp) |
| Load balancer | N | full L2-L4 decode, drop malformed, pick FP | `LoadBalancerStage` |
| Fast path | N x K | flow table, TCP state, SNI/Host, classify, rules, verdict | `FastPathStage`, [src/pipeline/flow_inspector.cpp](src/pipeline/flow_inspector.cpp) |
| Writer | 1 | write forwarded packets | `WriterStage` |

The route of a packet depends only on its flow hash `h`: `LB = h % N` and,
inside that LB's group, `FP = (h / N) % K`. Dividing by `N` before taking the
FP index means the two choices use different bits of `h`. Without it, with
N = K = 2, every flow on LB 0 would have an even hash and land on the same FP.

Because the route is a pure function of the flow, **every packet of a flow,
in both directions, goes through the same LB and the same FP**. Queues are
FIFO with exactly one producer for each LB and FP queue, so **per-flow order
is preserved**. Packets of *different* flows can leave in a different order
than they arrived, because FPs run independently. That is inherent to
parallel processing and harmless here: no consumer of the output relies on
the order across flows. If it mattered, the writer could reorder on
`Packet::seq` with a bounded reorder buffer.

The stages are plain single-threaded classes. `run_sequential`
([src/pipeline/sequential.cpp](src/pipeline/sequential.cpp)) chains them on
one thread; `run_pipeline` ([src/pipeline/pipeline.cpp](src/pipeline/pipeline.cpp))
gives each its own thread. Both modes run the same code, so the determinism
test ([tests/integration/test_determinism.cpp](tests/integration/test_determinism.cpp))
compares real behaviour: every count, per-app total, SNI tally and verdict of
the threaded pipeline must equal the sequential baseline, across seven
layouts that vary thread counts, queue capacity (down to 1) and batch size
(1 to 1000).

## 2. Per-thread flow tables instead of one locked table

Each FP owns a `FlowTable` ([src/flow/flow_table.cpp](src/flow/flow_table.cpp))
that no other thread ever touches, so lookups and updates need no locks.

A single global table behind a mutex would make every packet on every
thread contend for one lock, and the critical section (hash lookup, TCP
state, maybe SNI parsing) is long. Throughput would flatten as threads are
added. Striped locks or a concurrent hash map reduce contention but still
pay for atomics and cache-line transfers on every packet, and they make flow
state such as reassembly buffers harder to reason about.

Partitioning by flow avoids all of that. It works only because of flow
affinity (section 1): the FP that owns a flow is the only one that ever sees
it. The costs are:

* **No global view while running.** Statistics are kept per thread and
  merged after `join()`. That suffices for a batch tool. A live dashboard
  would need per-thread snapshots.
* **Per-FP capacity.** `max_flows` applies per table. A skewed distribution
  can fill one table while others are empty (see section 6).
* **Load balance depends on the hash** (section 6).

The table itself is a `std::unordered_map` from key to a node in a
`std::list` kept in least-recently-used order. Lookup, insert, touch and
capacity eviction are O(1). Idle sweeps walk from the old end and stop at
the first live flow, so a sweep costs O(number of expired flows).
`std::list::splice` relinks nodes without moving them, so a `FlowEntry*`
stays valid while other flows come and go.

### Time and determinism

All time comes from packet timestamps, never the wall clock, so results do
not depend on how fast the file is replayed. Idle expiry is checked
**lazily, per flow, on lookup**: a packet arriving more than
`idle_timeout` after its own flow's `last_seen` starts a new flow. Periodic
sweeps only reclaim memory. Since one FP's sweep schedule cannot change any
flow's boundaries, flow counts are identical for every thread layout. The
one exception is hitting `max_flows`: which flow gets evicted depends on how
flows are spread across tables, so the guarantee holds only below capacity.

Per-app and per-SNI statistics are recorded when a flow *leaves* the table
(through a retire callback), the way NetFlow exports flow records. Every
packet of a flow is therefore counted under its final classification, and
the totals do not depend on timing.

## 3. Why the 5-tuple is normalized before hashing

A connection's two directions have mirrored tuples: `A:p -> B:q` and
`B:q -> A:p`. Hashing them as-is would give two different hashes, so the
two directions could go to different FPs. Each FP would then hold half a
connection. The SYN and the SYN-ACK would never meet, and the server's
replies would land in a flow table that never saw the ClientHello and so
does not know the flow is blocked.

`normalize()` ([src/flow/five_tuple.cpp](src/flow/five_tuple.cpp)) stores the
endpoint `(ip, port)` that compares smaller first and records which
direction the packet went (`Direction::LoToHi/HiToLo`). Both directions get
the same key and hash, and the direction flag keeps per-direction counters
correct. Whole endpoints are compared (IP, then port), so two connections
between the same pair of hosts on different ports stay distinct.

`flow_hash` is FNV-1a over the field values in a fixed byte order, followed
by the MurmurHash3 64-bit finalizer. The fixed order makes the hash
independent of struct padding and host endianness. The finalizer matters
because routing uses `h % N`: FNV-1a's low bits depend only weakly on the
last input bytes, and without mixing, flows that differ only in their client
port would cluster. A test checks an even spread over 16 workers, and the
hash value is pinned against an independent Python implementation.

The reader computes the hash from a cheap `peek_tuple()` before the full
decode. A unit test and a fuzz target check that, for every packet the
full parser accepts, `peek_tuple` gives exactly the same tuple. Otherwise a
flow could be routed by one tuple and tracked by another.

## 4. Bounded queues, backpressure and shutdown

`BoundedBlockingQueue<T>` ([include/dpi/concurrency/bounded_queue.hpp](include/dpi/concurrency/bounded_queue.hpp))
is one mutex and two condition variables (`not_full_`, `not_empty_`) over a
ring buffer allocated once at construction.

* **Bounded = backpressure.** The reader can produce packets much faster
  than inspection consumes them. With an unbounded queue it would buffer the
  whole capture in memory. With a bound, a full queue blocks the producer,
  and a slow stage slows everything upstream of it, which caps memory at
  roughly `capacity x queues x packet size`.
* **Items move by value, in batches.** `Packet` is move-only (its bytes
  live in a `std::vector`), so moving one moves three pointers and never
  copies payload. There is no per-packet `shared_ptr` and so no atomic
  reference-count traffic. The pipeline queues carry `std::vector`s of up
  to `batch_size` (64) items. A `Batcher` per producer thread
  ([src/pipeline/pipeline.cpp](src/pipeline/pipeline.cpp)) fills one batch
  per destination, pushes it when full, and flushes partial batches after
  every input batch. That way a packet never waits for unrelated traffic,
  and latency stays bounded by one batch. Section 9 explains why this
  matters.
* **Notify after unlock**, so a woken thread does not immediately block on
  the mutex its waker still holds.
* **`close()`** makes `push` fail and lets `pop` keep returning items until
  the queue is empty, then return `nullopt`. Consumers drain everything that
  was accepted and then exit, without any sentinel ("poison pill") packets.

### Ordered shutdown

1. The reader reaches EOF and closes every LB queue.
2. Each LB drains its queue, then closes **its own** FP queues. It can do
   so safely because it is their only producer.
3. Each FP drains its queue, retires its flows into its statistics and
   exits.
4. The main thread joins the reader, the LBs and the FPs, in that order,
   then closes the writer queue, which has many producers and so can only
   be closed once all of them are gone.
5. The writer drains, flushes and exits. Stats are merged after the last
   `join()`, which provides the happens-before edge for reading them.

### Failure

Each thread body runs inside a `try` block. The first exception (a disk
write error, say) is recorded, and **every queue is closed**, so every
blocked `push`/`pop` returns and every thread reaches its exit path. After
all joins, the exception is rethrown to the caller. If starting a thread
fails partway, the threads already started are stopped and joined the same
way. Tests inject reader and writer failures with 2-slot queues, where a
missed wake-up would deadlock.

## 5. Parsing hostile input safely

Every byte comes from an untrusted capture, so the parsers are written
around a few rules.

* **Check a header's whole length before reading any of its fields**, and
  read multi-byte fields with `memcpy` plus `ntohs`/`ntohl`
  ([include/dpi/common/bytes.hpp](include/dpi/common/bytes.hpp)). Packet
  bytes are not aligned, so casting a pointer to `uint16_t*` would be
  undefined behaviour. The loads `assert` their bounds in debug and
  sanitizer builds, catching any missing check.
* **Variable-length structures use `ByteCursor`**
  ([include/dpi/common/byte_cursor.hpp](include/dpi/common/byte_cursor.hpp)),
  whose reads fail instead of overrunning. `sub(n)` splits off a nested
  structure so it can never read past its declared length.
* **Lengths are validated against both the declared and the captured
  size.** An IPv4 total length longer than the frame is legitimate only if
  the capture was cut by snaplen (`caplen < origlen`); otherwise the header
  is lying and the packet is malformed. Bytes beyond the IP total length
  (Ethernet padding) are never treated as payload.
* **The PCAP reader never trusts a record length.** A `caplen` above
  256 KiB is reported as corrupt and never allocated. A truncated final
  record is counted, not crashed on.
* **Strict TLS parsing.** The ClientHello walk validates every length, the
  entire extension list, and duplicate `server_name` extensions. An
  inconsistent hello is either corrupt or crafted to evade filtering, so
  its SNI is not trusted. Names are canonicalized and validated before they
  reach the classifier, the rules or the report.
* **Malformed packets are counted by reason** (`truncated_tcp`,
  `bad_ip_header_length`, ...) and not forwarded.

How this is checked:

* every header truncated at every byte, each cut copied into an exact-size
  buffer so ASan sees any 1-byte over-read;
* every TLS length field corrupted on its own;
* 20,000-iteration seeded mutation tests;
* libFuzzer targets for the parser and for SNI/Host extraction, which also
  assert the `peek_tuple` property above;
* the whole suite under ASan+UBSan (with `-fno-sanitize-recover`) and TSan
  in CI.

IP checksums are deliberately not verified. Captures taken on hosts with
checksum offload routinely contain "bad" checksums, and a passive inspector
should not drop traffic the network delivered.

## 6. Hash skew and elephant flows

Hash routing balances **flows**, not **bytes**. With many flows of similar
size, the per-FP packet counts in the report are close to even
(`many_flows.pcap` on 2x4: every FP gets between 11.6% and 13.5% of
packets). But one large flow, such as a backup or a video stream, always
goes to one FP, and that FP's share of the work grows with it. The other
FPs cannot help, because helping would break flow affinity and require
shared flow state.

Mitigations, roughly in order of cost:

* **More FPs than cores does not help** an elephant: it lives on one thread
  regardless.
* **Keep the fast path cheap.** After classification a flow's packets do a
  hash lookup, a few counter updates and a verdict check, so even an
  elephant costs little per packet. That is the point of stopping
  inspection early.
* **Rebalance on observation.** Detect a hot FP and re-route new flows
  (never existing ones) with a different hash seed or a weighted mapping.
  Existing flows stay put, so affinity holds.
* **Hand elephants off.** Once a large flow is classified and forwarded,
  later packets could skip the FP entirely (hardware offload or a
  verdict cache at the LB), as many production systems do.

None of these are implemented. The report's per-thread packet counts exist
so that skew is visible.

## 7. Inspection, classification and rules

* **Fast path.** `FlowInspector` looks at only the first 4 payload packets
  of a TCP flow. The client's first payload is tried as a TLS ClientHello,
  then as an HTTP/1.x request. When the SNI or Host is found (or inspection
  gives up), `inspection_done` is set and the flow is never inspected
  again. UDP flows are classified by port alone.
* **Minimal reassembly.** If the ClientHello or request is split across
  TCP segments (common with large, post-quantum key-share ClientHellos), the
  inspector buffers the client's bytes while the segments arrive exactly in
  sequence, up to 16 KiB, and retries. Out-of-order segments, a gap, or a
  snaplen-cut segment end inspection with the port-based app. That is not
  TCP reassembly: no retransmission handling, no windows, no server side.
* **Classifier.** A data-driven suffix table
  ([src/classifier/classifier.cpp](src/classifier/classifier.cpp)) is
  searched by stripping one leading label at a time, so matches fall on
  label boundaries (`netflix.com` does not match `x.com`) and the longest
  suffix wins (`googlevideo.com` is YouTube, not Google). Without a name, a
  port table guesses (443 HTTPS, 53 DNS, UDP 443 QUIC).
* **Rules** ([src/rules/rule_set.cpp](src/rules/rule_set.cpp)) are parsed
  once into hash sets and bitsets and shared read-only as
  `shared_ptr<const RuleSet>`. Each FP copies that pointer once at
  construction, never per packet. A flow is checked when it is created (so
  ip, port and port-based app rules drop it from the SYN onward) and once
  more when inspection finishes. **Packets sent before the SNI is known,
  typically the TCP handshake, are forwarded.** A firewall that must not
  leak even a SYN needs IP or port rules. Verdicts are per flow and sticky.
  A new SYN reusing a closed connection's 5-tuple starts a new flow and is
  judged afresh.

## 8. What was left out, and why

| Left out | Why | What it would take |
|---|---|---|
| IPv6 | Was a stretch goal; a v4-only implementation keeps the parser, key and hash simple. IPv6 frames are counted and forwarded unparsed. | 128-bit addresses in the key and hash, an extension-header walk with the same bounds discipline, and fragment headers. |
| Full TCP reassembly | Most SNIs fit in the first segment, and the minimal in-order reassembly handles the common split case. Full reassembly needs per-flow buffers, retransmission and overlap policy, which is a large attack surface. | A per-flow segment tree keyed by sequence number, with memory limits and an overlap policy. |
| TLS 1.3 ECH | With Encrypted Client Hello the real SNI is encrypted. Only the outer, public name is visible, and that is what the engine reports. | Nothing on a passive tap. It needs DNS-based policy or endpoint cooperation. |
| QUIC (HTTP/3) | The QUIC Initial is encrypted with keys derived from the connection ID. Extracting the SNI needs HKDF and AES-GCM, which would require a crypto library. UDP 443 is reported as `QUIC` by port. | A crypto dependency plus CRYPTO-frame reassembly. |
| DNS query names | Stretch goal, not done. DNS flows are classified by port, so `block domain` does not affect DNS lookups. | Parse the question section of UDP 53 payloads, with compression-pointer loop protection. |
| Hot rule reload | Stretch goal, not done. A batch tool reads its rules once. `std::atomic<std::shared_ptr>` is not available on every standard library this builds with. | A version counter that FPs check each batch, plus a mutex-protected `shared_ptr` swap. Old rules stay alive until each FP has switched. |
| Double VLAN (QinQ) | One 802.1Q tag covers most captures. A second tag leaves the frame classified as non-IP and forwarded. | Loop over up to two tags. |
| Lock-free SPSC queue | Stretch goal, not done. With batching, the queues stopped being the bottleneck: the best layout reaches 83% of the reader thread's ceiling (section 9). | A ring buffer with acquire/release indices for the single-producer LB and FP queues, benchmarked against the mutex queue. |

## 9. Performance: what the benchmark showed

All figures are from [bench/RESULTS.md](bench/RESULTS.md): 1M packets
replayed from memory on an Apple M2.

* **Per-packet hand-off lost to a single thread.** The sequential baseline
  does all four stages in about 147 ns per packet (6.8 Mpps). The first
  pipeline passed packets one at a time. Each hop took the queue mutex and
  usually woke a sleeping consumer through its condition variable (a
  syscall and a context switch), which cost more than the work being handed
  over. Every threaded layout was slower than one thread (2.5 Mpps with
  1 FP, 0.6 Mpps with 8), and more threads made it worse. `--batch-size 1`
  still reproduces this.
* **Batching fixed it.** With batches of 64, one lock and one wake-up cover
  64 packets. The pipeline reaches 9.5 Mpps with a single FP and
  11.35 Mpps at best (1 LB x 4 FP), 1.67x the baseline.
* **The reader is now the ceiling.** The reader stage alone, with nothing
  downstream, runs at 13.6 Mpps, and the best layout reaches 83% of that.
  Past 2-4 FPs, adding threads cannot help (Amdahl's law), and the 8-FP
  layouts (12-14 threads on 8 cores, half of them efficiency cores) lose
  ground to oversubscription. The reader's cost is dominated by
  allocating and filling a fresh buffer for every packet. Recycling buffers
  through a pool is the next optimization. At real line rate, NIC RSS
  would give every core its own ingestion queue, removing the single reader
  entirely.
* **Inspection is cheap** because it stops early: with 18.7% of packets
  dropped by rules, throughput stays within run-to-run noise of the no-rules
  case.
