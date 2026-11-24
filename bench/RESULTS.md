# Raw benchmark output

Output of `bench_pipeline` (only the headings and code fences were added) on `bench/data/bench.pcap` (generated
by `python3 tools/gen_bench_pcap.py`: 1,008,000 packets, 24,000 flows). The README
summarises these runs.

```
date: 2026-11-24T19:39Z
machine: Apple M2, 4 performance + 4 efficiency cores, 8 GB RAM, macOS 27.0.1
compiler: Apple clang version 21.0.0 (clang-2100.3.34.2), CMake Release (-O3)
background: CPU usage: 15.31% user, 8.68% sys, 76.0% idle 
```

### batch 64, no rules
capture: bench/data/bench.pcap (424.5 MB), hardware threads: 8, queue size: 4096, batch size: 64, rules: none, repeats: 7 (median)

| Layout | FP threads | Threads total | Mpps | Gbps | Mpps min-max |
|---|---:|---:|---:|---:|---:|
| sequential (1 thread) | 1 | 1 | 6.79 | 21.99 | 5.85-7.13 |
| 1 LB x 1 FP | 1 | 4 | 9.48 | 30.73 | 9.32-10.03 |
| 1 LB x 2 FP | 2 | 5 | 10.53 | 34.12 | 6.84-10.71 |
| 2 LB x 2 FP | 4 | 8 | 9.74 | 31.56 | 9.36-9.85 |
| 2 LB x 4 FP | 8 | 12 | 7.10 | 23.01 | 5.61-7.53 |
| 1 LB x 4 FP | 4 | 7 | 11.35 | 36.80 | 10.07-11.42 |
| 4 LB x 2 FP | 8 | 14 | 8.70 | 28.20 | 7.64-8.75 |

reader stage alone (upper bound for any layout): 13.61 Mpps (median)

### batch 64, rules/example_rules.txt
capture: bench/data/bench.pcap (424.5 MB), hardware threads: 8, queue size: 4096, batch size: 64, rules: rules/example_rules.txt, repeats: 7 (median)

| Layout | FP threads | Threads total | Mpps | Gbps | Mpps min-max |
|---|---:|---:|---:|---:|---:|
| sequential (1 thread) | 1 | 1 | 6.86 | 22.25 | 6.78-6.96 |
| 1 LB x 1 FP | 1 | 4 | 9.36 | 30.33 | 9.30-9.70 |
| 1 LB x 2 FP | 2 | 5 | 10.28 | 33.32 | 9.96-10.40 |
| 2 LB x 2 FP | 4 | 8 | 9.27 | 30.03 | 8.99-9.43 |
| 2 LB x 4 FP | 8 | 12 | 7.61 | 24.66 | 5.12-7.92 |
| 1 LB x 4 FP | 4 | 7 | 10.28 | 33.33 | 2.43-11.41 |
| 4 LB x 2 FP | 8 | 14 | 8.05 | 26.10 | 7.79-8.41 |

reader stage alone (upper bound for any layout): 13.28 Mpps (median)

### batch 1 (per-packet hand-off), no rules
capture: bench/data/bench.pcap (424.5 MB), hardware threads: 8, queue size: 4096, batch size: 1, rules: none, repeats: 5 (median)

| Layout | FP threads | Threads total | Mpps | Gbps | Mpps min-max |
|---|---:|---:|---:|---:|---:|
| sequential (1 thread) | 1 | 1 | 6.92 | 22.43 | 6.51-6.97 |
| 1 LB x 1 FP | 1 | 4 | 2.52 | 8.15 | 1.60-2.80 |
| 1 LB x 2 FP | 2 | 5 | 2.01 | 6.53 | 1.09-2.62 |
| 2 LB x 2 FP | 4 | 8 | 1.04 | 3.37 | 0.58-1.49 |
| 2 LB x 4 FP | 8 | 12 | 0.60 | 1.95 | 0.56-0.79 |
| 1 LB x 4 FP | 4 | 7 | 1.41 | 4.57 | 1.32-1.57 |
| 4 LB x 2 FP | 8 | 14 | 0.55 | 1.78 | 0.49-0.69 |

reader stage alone (upper bound for any layout): 14.06 Mpps (median)
