"""Guard: the shipped overrides template stays truthful (build 90).

The pak ships content/files/solutionconfig/compliance_overrides_template.xml,
which VCF Operations imports into its configuration-file store. Admins copy
it and uncomment entries, so the template must:

* be well-formed XML with a ComplianceOverrides root and no live entry
  (the adapter's own parser test, OverridesTest, checks the same from Java);
* name only control ids that exist in the bundled canonical profiles;
* list exactly the bundled SCG versions;
* carry no em-dash (house style).

Standard library only. Run from the repo root:
  python3 tests/test_overrides_template.py
"""

import csv
import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TEMPLATE = (REPO / "content" / "files" / "solutionconfig"
            / "compliance_overrides_template.xml")
CANONICAL = REPO / "profiles" / "canonical"


def control_ids() -> set:
    ids = set()
    for f in CANONICAL.glob("scg_*.csv"):
        with f.open(encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                ids.add(row["control_id"])
    return ids


class TemplateTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.text = TEMPLATE.read_text(encoding="utf-8")

    def test_well_formed_with_no_live_entry(self):
        root = ET.fromstring(self.text.encode("utf-8"))
        self.assertEqual(root.tag, "ComplianceOverrides")
        self.assertEqual(list(root), [], "every entry must be commented out")

    def test_every_example_control_exists(self):
        named = set(re.findall(r'control="([^"]+)"', self.text))
        self.assertTrue(named, "the template shows at least one example")
        self.assertEqual(named - control_ids(), set())

    def test_versions_match_the_bundled_profiles(self):
        bundled = sorted(p.stem.split("_", 1)[1]
                         for p in CANONICAL.glob("scg_*.csv"))
        line = re.search(r"Versions: (.*)", self.text).group(1)
        listed = re.findall(r"SCG (\d+\.\d+)", line)
        self.assertEqual(listed, bundled)

    def test_password_attempts_example(self):
        self.assertIn('<Override control="esx.account-lockout-max-attempts" '
                      'expected="5"/>', self.text)
        for kind in ("Skip control=", "Override control=", "Profile kind="):
            self.assertIn(kind, self.text)

    def test_no_instance_wide_profile_example(self):
        # Build 92: a Profile without kind is rejected, so the template
        # must not show one.
        for entry in re.findall(r"<Profile\b[^>]*>", self.text):
            self.assertIn("kind=", entry, entry)

    def test_no_em_dash(self):
        self.assertNotIn("\u2014", self.text)


if __name__ == "__main__":
    unittest.main()
