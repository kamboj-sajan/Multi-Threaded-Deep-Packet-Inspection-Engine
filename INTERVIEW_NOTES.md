# Interview notes

Twenty questions an interviewer is likely to ask about this codebase, with
short answers that point to where the code lives. [DESIGN.md](DESIGN.md)
has the longer reasoning.

---

### 1. Walk me through the life of one packet.

1. **Reader thread** (`ReaderStage::next`, [src/pipeline/stages.cpp](src/pipeline/stages.cpp)).
   `PcapReader::next` reads a record into a move-only `Packet`
   ([src/pcap_io/pcap_reader.cpp](src/pcap_io/pcap_reader.cpp)). `routing_hash`
   peeks at the 5-tuple and hashes it, and the packet is batched toward
   `LB[h % N]`.
2. **LB thread** (`LoadBalancerStage::process`). `parse_packet` fully decodes
   L2-L4 into a `ParsedPacket` (offsets only, no copies). Malformed packets
   are counted by reason and dropped. Valid ones go to `FP[(h / N) % K]` in
   this LB's group.
3. **FP thread** (`FastPathStage::process`). Flow lookup/insert, TCP state,
   `FlowInspector::inspect` (SNI/Host) for the first few payload packets,
   `apply_rules`, then the flow's verdict.
4. **Writer thread** (`WriterStage::write`). Forwarded packets are appended
   to the output PCAP.

The wiring, queues and shutdown are in `Pipeline`
([src/pipeline/pipeline.cpp](src/pipeline/pipeline.cpp)).

### 2. Why split the work into reader, LB and FP stages?

Reading a file is inherently sequential, so there is one reader, and it does
as little as possible: read, peek, hash. Full decoding is parallel work, so
it moves to N LBs. Flow-stateful work (tables, inspection, rules) runs in
N x K FPs, partitioned by flow. Giving each LB its own group of FPs means
every FP queue has exactly one producer. That keeps per-flow order trivially
FIFO and lets each LB close its own FP queues at shutdown.

### 3. How do both directions of a TCP connection reach the same FP?

`normalize()` ([src/flow/five_tuple.cpp](src/flow/five_tuple.cpp)) stores the
smaller `(ip, port)` endpoint first and records the packet's `Direction`, so
`A->B` and `B->A` give the same `FiveTuple` and the same `flow_hash`. The
route depends only on that hash. The reader hashes the output of the cheap
`peek_tuple`, and the FP keys its table on the full parse. A unit test
(`PeekTuple.MatchesFullParseForEveryAcceptedShape`) and a fuzz target
(`fuzz/fuzz_packet_parser.cpp`) assert that the two always agree.

### 4. Why FNV-1a plus a finalizer, and why `(h / N) % K`?

FNV-1a over the field values in a fixed byte order is simple and
independent of struct padding and host endianness. Its low bits mix poorly,
and routing uses `h % N`, so the MurmurHash3 finalizer (`avalanche`)
spreads every input bit into every output bit. `FiveTuple.HashSpreadsEvenlyOverWorkers`
checks the balance, and `HashIsPinnedAcrossPlatforms` pins a value computed
independently in Python. Using `h % N` for the LB and then `(h / N) % K` for
the FP gives the two choices different bits. With `h % K` instead, at N = K = 2,
every flow on LB 0 would have an even hash and land on FP 0.

### 5. Why per-thread flow tables rather than one shared table?

A global table needs a lock or atomics on every packet, and the critical
section is long, so contention grows with the thread count. With flow
affinity, a flow is only ever seen by one FP, so each `FlowTable`
([src/flow/flow_table.cpp](src/flow/flow_table.cpp)) is single-owner and
lock-free by construction. It is an `unordered_map` into an LRU `std::list`:
O(1) lookup, touch and eviction, and sweeps that stop at the first live
flow. Time comes from packet timestamps. Expiry is checked lazily per flow
on lookup, so sweep timing cannot change results. The trade-offs are no
live global view (stats merge after `join`) and per-table capacity.

### 6. How is `BoundedBlockingQueue` implemented, and why two condition variables?

[include/dpi/concurrency/bounded_queue.hpp](include/dpi/concurrency/bounded_queue.hpp):
a mutex, `not_full_` and `not_empty_`, over a ring buffer of
`std::optional<T>` allocated once. Producers wait on `not_full_` and
consumers on `not_empty_`, so a push only ever wakes a consumer and a pop
only ever wakes a producer. With one condition variable, `notify_one` could
wake the wrong kind of waiter. The wait predicates guard against spurious
wake-ups, and notification happens after unlocking.

### 7. What happens when the writer is slower than the reader?

Its queue fills, `push` blocks the FPs, their input queues fill, and so on
back to the reader, which stops reading. Memory stays bounded by queue
capacity instead of growing with the capture size. `BoundedQueue.PushBlocksUntilSpaceIsFreed`
tests this directly.

### 8. How does shutdown work without "poison pill" messages?

`close()` makes `push` fail, while `pop` keeps returning items until the
queue is empty and then returns `nullopt`. The order is: reader EOF closes
the LB queues; each LB drains, then closes its own FP queues (it is their
only producer); FPs drain and retire their flows; the main thread joins
reader, LBs and FPs, then closes the writer queue (many producers, so only
after all are gone) and joins the writer. See `Pipeline::run`.

### 9. What happens if a thread throws, say on a disk-full write?

`Pipeline::spawn` wraps every thread body. The first exception is stored in
a `FailureLatch` and `abort_all()` closes every queue, so all blocked
`push`/`pop` calls return and every thread exits. After the joins, the
exception is rethrown to the caller. If thread creation itself fails, the
threads already started are stopped and joined. Tested by
`PipelineThreads.WriterFailure...` and `ReaderFailure...`, using 2-slot queues
where a lost wake-up would hang the test.

### 10. How do you know there are no data races?

By design: every stage object, flow table and stats struct is owned by one
thread. Threads share only the queues (mutex-protected) and the
`RuleSet`/`Classifier`, which are immutable. The main thread reads stats only
after `join()`, which is a happens-before edge. By test: the whole suite runs
under ThreadSanitizer in CI, including an MPMC queue stress test (200k items,
capacity 8), determinism runs with 1-slot queues, and 8 threads evaluating
one `RuleSet`. I also confirmed that TSan does flag a deliberate race on the
build machine, so a clean run means something.

### 11. Is the threaded version actually faster? What did you learn from benchmarking?

It is now, but the first version was not. Measured on an Apple M2 with
1M packets replayed from memory ([bench/RESULTS.md](bench/RESULTS.md)):

* **Per-packet hand-off.** The first version handed packets over one at a
  time. Each hop cost a mutex and usually a condition-variable wake-up (a
  syscall and a context switch), which is more than the roughly 147 ns of
  real work per packet. So **every threaded layout was slower than the
  6.8 Mpps single-threaded baseline**: 2.5 Mpps with 1 FP, falling to
  0.6 Mpps with 8.
* **Batching.** Moving packets in batches of 64 (`Batcher` in
  [src/pipeline/pipeline.cpp](src/pipeline/pipeline.cpp)) shares one lock
  and wake-up across the batch. The pipeline then reaches 9.5 Mpps with
  1 FP and 11.35 Mpps at best (1 LB x 4 FP), 1.67x the baseline.
* **What limits it now.** The best layout reaches 83% of the 13.6 Mpps the
  reader thread can produce on its own. The remaining limits are that one
  ingestion thread (Amdahl's law), and oversubscription when the layout
  needs more threads than the 8 cores.
* `--batch-size 1` still reproduces the per-packet numbers.

The lesson: measure the cost of a hand-off against the cost of the work
before adding threads.

### 12. How do you parse untrusted packets safely?

[src/parser/packet_parser.cpp](src/parser/packet_parser.cpp): check the whole
header length before reading any field; read fields with `memcpy` plus
`ntohs`/`ntohl` (`load_be16/32` in [include/dpi/common/bytes.hpp](include/dpi/common/bytes.hpp),
which `assert` bounds in debug builds); validate IHL >= 5, the TCP data
offset and the UDP length against both the declared and the captured size;
treat a length beyond the frame as malformed unless snaplen cut the capture.
The PCAP reader refuses `caplen` above 256 KiB. Tests cut every header at
every byte into exact-size buffers so ASan catches 1-byte over-reads, plus
20k seeded mutations and libFuzzer targets.

### 13. Walk me through ClientHello parsing.

`parse_tls_client_hello` ([src/inspect/tls_sni.cpp](src/inspect/tls_sni.cpp)),
using a bounds-checked `ByteCursor`:

1. Record header: type 0x16, version 3.x, length. If the whole record isn't
   here yet, return `Incomplete`.
2. Handshake type 0x01 and its u24 length.
3. Skip the version and the 32-byte random.
4. `session_id` (u8 length, at most 32).
5. `cipher_suites` (u16 length, even, at least 2).
6. `compression_methods` (u8 length, at least 1).
7. Extensions (u16 length, which must end exactly at the end of the hello).
   Walk every one, find type 0 (server_name), and inside it take name_type
   0 (host_name).

It is strict: any length mismatch, or a duplicate `server_name`, is
`Malformed` and the SNI is not trusted. The name goes through
`canonical_hostname`. Tests use a real ClientHello captured from OpenSSL
([tools/capture_client_hello.py](tools/capture_client_hello.py)), as well as
built hellos with no SNI, with 600 extensions, and with every length field
corrupted.

### 14. What if the ClientHello is split across TCP segments?

Large hellos (post-quantum key shares, padding) often span two segments, and
browsers randomize extension order, so the SNI can be in the second one.
`FlowInspector::inspect` ([src/pipeline/flow_inspector.cpp](src/pipeline/flow_inspector.cpp))
sees `Incomplete`, buffers the client's bytes, and appends later segments
only if `tcp_seq` is exactly the next expected one, up to 16 KiB. Then it
retries. Reordering, a gap or a snaplen cut ends inspection with the
port-based app. `tls_split.pcap` covers 2- and 3-segment hellos, an
out-of-order one, and a split HTTP request.

### 15. What does "fast path" mean in this engine?

Only the first 4 payload packets of a flow are inspected (`InspectionConfig`).
Once the SNI or Host is found, or inspection gives up, `inspection_done` is
set and the reassembly buffer is freed. From then on a packet costs one hash
lookup, a few counter updates and a verdict check: no payload parsing.
`Inspection.StopsInspectingOnceClassified` checks that a later payload
cannot change the result.

### 16. How does domain-to-app classification work?

`Classifier::app_for_host` ([src/classifier/classifier.cpp](src/classifier/classifier.cpp))
looks up the full name in a hash map built from a data table, then drops
one leading label at a time (`a.b.youtube.com`, then `b.youtube.com`, then
`youtube.com`). The first hit is the longest matching suffix, and matches
always fall on label boundaries, so `netflix.com` does not match `x.com`.
With no name, `app_for_port` guesses from the server port (443 HTTPS,
53 DNS, UDP 443 QUIC).

### 17. When are rules applied, and why does the handshake get through?

`FastPathStage::apply_rules` ([src/pipeline/stages.cpp](src/pipeline/stages.cpp))
runs when a flow is created, so ip, port and port-based app rules drop it
from the SYN onward, and again when inspection finishes, for app and domain
rules. Before the ClientHello arrives, the engine cannot know the domain, so
the SYN / SYN-ACK / ACK are forwarded and the flow is dropped from the
ClientHello on. Verdicts are sticky. A new SYN on a closed connection's
5-tuple is judged afresh. `FastPathRules.*` pins down exactly which packets
pass.

### 18. How is the `RuleSet` shared between threads?

`RuleSet::load_file` ([src/rules/rule_set.cpp](src/rules/rule_set.cpp)) builds
it once into hash sets and bitsets, and it is passed around as
`std::shared_ptr<const RuleSet>`. Each FP copies the pointer once at
construction, never per packet, so there is no reference-count traffic on
the hot path. Because it is const and never modified after construction,
concurrent reads need no lock. `Rules.ConcurrentReadersShareOneInstance`
runs 8 threads against one instance under TSan. Hot reload (not
implemented) would swap the pointer and let old readers finish with the old
rules.

### 19. How do you know the results are correct, not just consistent?

Two independent checks:

* **Determinism.** `run_sequential` and `run_pipeline` run the same stage
  objects. [tests/integration/test_determinism.cpp](tests/integration/test_determinism.cpp)
  requires identical counts, apps, SNIs and verdicts, the same set of output
  packets, and the same per-flow order, across 7 thread, queue and batch
  layouts.
* **Independent expectations.** [tools/gen_pcap.py](tools/gen_pcap.py)
  computes the expected counts, classifications and rule verdicts from what
  it generated, using its own Python model of the rules, and writes them to
  `tests/data/MANIFEST.md`. The integration tests assert those numbers. They
  found two generator bugs before any engine bug. `tcpdump -r` must read
  every output file.

### 20. How would this scale to real line rate, and what about elephant flows?

Hash routing balances flows, not bytes. An elephant flow pins one FP,
because splitting it would break flow affinity (DESIGN.md section 6). For
real line rate:

* Replace PCAP file reading with AF_XDP or DPDK, and let NIC RSS do the
  symmetric hashing into per-core queues. That removes the single-reader
  bottleneck.
* Use lock-free SPSC rings between pinned cores, and recycle packet buffers
  from a pool instead of allocating one per packet.
* Offload or cache verdicts for long-lived flows that are already
  classified.
* Add IPv6, real TCP reassembly, DNS names, and QUIC Initial decryption.
