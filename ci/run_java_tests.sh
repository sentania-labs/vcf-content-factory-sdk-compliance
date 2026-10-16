#!/usr/bin/env bash
# Compiles and runs the adapter's plain-main Java tests (no test
# framework, no external deps beyond a JDK; BcHandshakeTest also fetches
# the BouncyCastle TLS jars, see below), then the Python checks (stdlib
# only). Exits non-zero on any compile error or failed assertion. Run
# from anywhere:
#   ci/run_java_tests.sh
# Build 96 (issue #27): EVERY adapter source file is compiled, the
# SDK-dependent ones (ComplianceAdapter, ComplianceStitcher, the REST
# clients) included, against the test-only stubs in tests/stubs (no SDK
# jar, no framework jar; see tests/stubs/README.md). The stubs never ship:
# build-sdk compiles src/ only, against the real jars. Every *Test.java
# and every tests/test_*.py runs, so a new test cannot be added and
# silently skipped.
set -euo pipefail
cd "$(dirname "$0")/.."
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
javac -d "$out" -sourcepath src:tests:tests/stubs \
    src/com/vcfcf/adapters/compliance/*.java \
    tests/com/vcfcf/adapters/compliance/*.java
for f in tests/com/vcfcf/adapters/compliance/*Test.java; do
    t="$(basename "$f" .java)"
    # BcHandshakeTest needs the BouncyCastle jars; it runs below.
    [ "$t" = "BcHandshakeTest" ] && continue
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
for p in tests/test_*.py; do
    python3 "$p"
done
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
