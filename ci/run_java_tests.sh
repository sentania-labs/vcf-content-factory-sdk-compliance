#!/usr/bin/env bash
# Compiles and runs the adapter's plain-main Java tests (no test
# framework, no external deps beyond a JDK), then the alert generator's
# Python tests (stdlib only). Exits non-zero on any compile error or
# failed assertion. Run from anywhere:
#   ci/run_java_tests.sh
# The tested classes (loader, profile, selector, evaluator, rollup) have
# no VCF Ops SDK dependency, so no SDK jar is needed.
set -euo pipefail
cd "$(dirname "$0")/.."
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
javac -d "$out" -sourcepath src:tests \
    tests/com/vcfcf/adapters/compliance/*.java
for t in BenchmarkLoaderTest ProfileSetTest BenchmarkSelectorTest \
        ControlEvaluatorTest ComplianceRollupTest ComplianceDecisionsTest \
        MixedVersionSimulationTest; do
    java -cp "$out" "com.vcfcf.adapters.compliance.$t"
done
python3 tests/test_generate_compliance_alerts.py
