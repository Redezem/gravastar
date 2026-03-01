#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${1:-$ROOT_DIR/build}"

if [[ ! -f "$BUILD_DIR/CTestTestfile.cmake" ]]; then
  echo "[run_all_tests] configuring project in: $BUILD_DIR"
  cmake -S "$ROOT_DIR" -B "$BUILD_DIR"
fi

echo "[run_all_tests] building project in: $BUILD_DIR"
cmake --build "$BUILD_DIR"

echo "[run_all_tests] running all tests from: $BUILD_DIR"
ctest --test-dir "$BUILD_DIR" -V
