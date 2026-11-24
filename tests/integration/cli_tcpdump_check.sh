#!/bin/sh
# Runs the dpi_engine CLI on a capture and checks that tcpdump can read the
# output and finds the expected number of packets in it.
# usage: cli_tcpdump_check.sh <dpi_engine> <tcpdump> <input.pcap> <expected> [extra args...]
set -eu
engine=$1 tcpdump=$2 input=$3 expected=$4
shift 4
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

"$engine" "$input" "$workdir/out.pcap" --report "$workdir/report.json" "$@" > "$workdir/report.txt"

count=$("$tcpdump" -nn -r "$workdir/out.pcap" 2>/dev/null | wc -l | tr -d ' ')
if [ "$count" != "$expected" ]; then
  echo "tcpdump read $count packets from the output, expected $expected" >&2
  exit 1
fi
grep -q "\"forwarded\": $expected," "$workdir/report.json" || {
  echo "JSON report does not say forwarded=$expected" >&2
  cat "$workdir/report.json" >&2
  exit 1
}
echo "ok: tcpdump read $count packets"
