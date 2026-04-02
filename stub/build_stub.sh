#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Build without zlib (default)
gcc -O2 -o stub stub.c
echo "Built stub (without compression support)"

# Build with zlib support
gcc -O2 -DUSE_ZLIB -o stub_zlib stub.c -lz
echo "Built stub_zlib (with compression support)"
