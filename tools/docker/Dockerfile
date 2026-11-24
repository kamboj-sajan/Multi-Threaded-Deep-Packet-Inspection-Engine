# Linux build/test environment matching CI (ubuntu 24.04, GCC 13, Clang 18).
# Usage:
#   docker build -t dpi-dev tools/docker
#   docker run --rm -v "$PWD":/src -w /src dpi-dev tools/docker/ci_local.sh
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential g++ clang libclang-rt-18-dev cmake ninja-build tcpdump python3 ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
