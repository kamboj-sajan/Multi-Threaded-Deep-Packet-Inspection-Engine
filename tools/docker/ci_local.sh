#!/usr/bin/env bash
# Runs the CI matrix inside the Linux container. Build trees go to
# build-linux/ so they never clash with host (macOS) build trees.
set -euo pipefail
presets=("${@:-debug tsan}")
for preset in ${presets[@]}; do
  for compiler in gcc clang; do
    if [[ "$preset" == "tsan" || "$preset" == "asan-ubsan" ]] && [[ "$compiler" == "gcc" ]]; then
      continue  # sanitizer jobs use clang, as in CI
    fi
    if [[ "$compiler" == "gcc" ]]; then export CC=gcc CXX=g++; else export CC=clang CXX=clang++; fi
    dir="build-linux/${preset}-${compiler}"
    echo "=== ${preset} / ${compiler}"
    cmake --preset "$preset" -B "$dir" --fresh > /dev/null
    cmake --build "$dir"
    ctest --test-dir "$dir" --output-on-failure -j4
  done
done
