#!/usr/bin/env bash
# Compiles and runs the adapter's plain-main Java tests (no test
# framework, no external deps beyond a JDK). Exits non-zero on any
# compile error or failed assertion. Run from the repo root:
#   ci/run_java_tests.sh
set -euo pipefail
cd "$(dirname "$0")/.."
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
javac -d "$out" -sourcepath src \
    tests/com/vcfcf/adapters/compliance/BenchmarkLoaderTest.java \
    src/com/vcfcf/adapters/compliance/BenchmarkLoader.java
java -cp "$out" com.vcfcf.adapters.compliance.BenchmarkLoaderTest
