#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

gcc -o jules jules.c
gcc -o vincent vincent.c

echo "Built test fixtures: jules, vincent"
