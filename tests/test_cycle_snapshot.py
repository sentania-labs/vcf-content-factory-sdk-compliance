"""Guard: review N13 (build 95). One set of clients and one account per cycle.

configureAdapter writes only the configured* fields; collectWorld copies
them, and the account, once at the start of the cycle; the cycle code
reads only the copies. So an instance edit during a cycle never switches
that cycle to the new vCenter part-way (where a moRef such as host-12
could name a different object). The adapter needs the VCF Ops SDK, which
the plain-main Java tests do not load, so this pins the source shape.
Standard library only. Run from the repo root:
    python3 tests/test_cycle_snapshot.py
"""

import re
import unittest
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / "src/com/vcfcf/adapters/"
       "compliance/ComplianceAdapter.java").read_text(encoding="utf-8")
FIELDS = ["vsphere", "benchmarkLoader", "suiteStitcher", "stitcher"]


def method(start):
    """The text from a method signature to the next top-level member."""
    i = SRC.index(start)
    m = re.compile(r"^\t(?:@Override|/\*\*|private |protected |public )",
                   re.M).search(SRC, i + len(start))
    return SRC[i:m.start() if m else len(SRC)]


class CycleSnapshotTest(unittest.TestCase):

    def test_configure_writes_only_configured(self):
        body = method("protected void configureAdapter(")
        for f in FIELDS:
            self.assertNotRegex(body, r"\bthis\.%s\s*=" % f, f)
        for f in ["configuredVsphere", "configuredLoader",
                  "configuredSuite", "configuredStitcher"]:
            self.assertRegex(body, r"\bthis\.%s\s*=" % f, f)

    def test_cycle_copies_once_at_start(self):
        body = method("private void collectWorld(")
        start = body.index("try {")
        head = body[:start]
        self.assertIn("cycleConfig = config;", head)
        for f, c in [("vsphere", "configuredVsphere"),
                     ("benchmarkLoader", "configuredLoader"),
                     ("suiteStitcher", "configuredSuite"),
                     ("stitcher", "configuredStitcher")]:
            self.assertIn("%s = %s;" % (f, c), head)
        # Nowhere else assigns the per-cycle copies.
        for f in FIELDS + ["cycleConfig"]:
            self.assertEqual(
                len(re.findall(r"^\s*(?:this\.)?%s\s*=[^=]" % f, SRC,
                               re.M)), 1, f)

    def test_cycle_reads_the_account_copy(self):
        i = SRC.index("private void collectWorld(")
        j = SRC.index("public void onDiscard()")
        cycle = SRC[i:j]
        self.assertEqual(re.findall(r"(?<![\w.])config\.", cycle), [])

    def test_discard_releases_configured(self):
        self.assertIn("releaseClients(configuredVsphere, configuredSuite)",
                      method("public void onDiscard()"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
