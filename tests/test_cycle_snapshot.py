"""Guard: review N13 and W12 (build 95). One holder per configuration.

configureAdapter builds one Configured holder (account, clients, the
state a cycle hands to the next) and publishes it with one write;
collectWorld copies that reference once, at the start of the cycle, and
the cycle code works only through the copy. So an instance edit during a
cycle never switches that cycle to the new vCenter part-way (where a
moRef such as host-12 could name a different object), and what the old
cycle records stays in the old holder. The adapter needs the VCF Ops SDK,
which the plain-main Java tests do not load, so this pins the source
shape (SnapshotHolderTest runs the holder itself). Standard library only.
Run from the repo root:
    python3 tests/test_cycle_snapshot.py
"""

import re
import unittest
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / "src/com/vcfcf/adapters/"
       "compliance/ComplianceAdapter.java").read_text(encoding="utf-8")


def method(start):
    """The text from a method signature to the next top-level member."""
    i = SRC.index(start)
    m = re.compile(r"^\t(?:@Override|/\*\*|private |protected |public )",
                   re.M).search(SRC, i + len(start))
    return SRC[i:m.start() if m else len(SRC)]


class CycleSnapshotTest(unittest.TestCase):

    def test_configure_publishes_one_holder(self):
        body = method("protected void configureAdapter(")
        self.assertEqual(len(re.findall(r"\bthis\.configured\s*=[^=]",
                                        body)), 1)
        self.assertNotRegex(body, r"\bthis\.config\s*=")

    def test_cycle_copies_once_at_start(self):
        body = method("private void collectWorld(")
        head = body[:body.index("try {")]
        self.assertIn("c = configured;", head)
        self.assertIn("cycle = c;", head)
        self.assertEqual(
            len(re.findall(r"^\s*(?:this\.)?cycle\s*=[^=]", SRC, re.M)), 1)

    def test_cycle_reads_the_account_copy(self):
        i = SRC.index("private void collectWorld(")
        j = SRC.index("public void onDiscard()")
        cycle = SRC[i:j]
        self.assertEqual(re.findall(r"(?<![\w.])config\.", cycle), [])

    def test_discard_releases_configured(self):
        self.assertIn("releaseClients(c.vsphere, c.suite)",
                      method("public void onDiscard()"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
