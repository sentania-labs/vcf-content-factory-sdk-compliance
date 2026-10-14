#!/usr/bin/env bash
# Compiles and runs the adapter's plain-main Java tests (no test
# framework, no external deps beyond a JDK; BcHandshakeTest also fetches
# the BouncyCastle TLS jars, see below), then the alert generator's
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
        MixedVersionSimulationTest Build74ReadPathsTest \
        Build76CleanupAbsentTest Build77FaultTest \
        EnvironmentKeyContractTest EsxcliCycleCacheTest OverridesTest \
        CertificateTest Build95CollectionTest Build95TriageTest; do
    java -cp "$out" "com.vcfcf.adapters.compliance.$t"
done

# Build 94: real handshakes under the BouncyCastle JSSE provider, the TLS
# provider of VCF Operations 9.1.1 collectors. The jars come from Maven
# Central (public, no credentials) with pinned SHA-256s; they are test
# only and never ship in the pak. In CI a failed fetch fails the run; on
# a workstation without network the test is skipped and says so.
bc_version=1.82
bc_dir="$out/bc"
mkdir -p "$bc_dir"
bc_ok=1
bc_skipped=0
while read -r art sum; do
    jar="$art-jdk18on-$bc_version.jar"
    url="https://repo1.maven.org/maven2/org/bouncycastle/$art-jdk18on/$bc_version/$jar"
    if ! curl -fsSL --retry 3 -o "$bc_dir/$jar" "$url"; then
        bc_ok=0
        break
    fi
    echo "$sum  $bc_dir/$jar" | sha256sum -c --quiet - || {
        echo "BouncyCastle $jar checksum mismatch" >&2
        exit 1
    }
done <<'SUMS'
bcprov 14cde2fdfaa8890480a8e5b67aceef0c90f96682c1e23c133bafdc9e0b3255ce
bctls 0f4d9d69ab9e1d0d11f3ae399edf77e0fd8af50aa93f565af5beeca222abad30
bcutil 4420691958ad1c0ba275a6d6d8a6317adbdbdc9277055b6a72aa89c88cda8c7d
SUMS
if [ "$bc_ok" = 1 ]; then
    java -cp "$out:$bc_dir/*" com.vcfcf.adapters.compliance.BcHandshakeTest
elif [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    echo "BouncyCastle jars could not be fetched from Maven Central" >&2
    exit 1
else
    bc_skipped=1
fi
python3 tests/test_generate_compliance_alerts.py
python3 tests/test_describe_symptom_sets.py
python3 tests/test_describe_account_dialog.py
python3 tests/test_dashboard_alert_lists.py
python3 tests/test_dashboard_widget_types.py
python3 tests/test_overrides_template.py
python3 tests/test_pass_rate_bindings.py
python3 tests/test_build95_dashboards.py
# Printed last and on stdout so a passing exit code on a workstation is
# not mistaken for a run that exercised the BouncyCastle handshakes.
if [ "$bc_skipped" = 1 ]; then
    echo
    echo "################################################################"
    echo "## SKIPPED: BcHandshakeTest was NOT run. The BouncyCastle jars"
    echo "## could not be fetched from Maven Central (offline?). The 9.1.1"
    echo "## collector TLS path is untested in this run; CI runs it."
    echo "################################################################"
fi
