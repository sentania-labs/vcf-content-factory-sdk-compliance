"""Guard: build 95 dashboard and view fixes from the open-issue triage.

- #39: the Compliance by vCenter and Object Type view shows
  Rollup|<Kind>|unmatched ("<Kind> Not in VCF Ops") beside each kind's
  scored and non-compliant counts, and sums it in the totals row.
- #32: Objects by SCG Version lists every bundled bucket newest first
  (9.1, 9.0, 8.0, 7.0, 6.7, none, unknown) and is full width on both
  dashboards that show it.
- #33: the Host Score Heatmap uses a fixed 0 to 100 scale with solid
  bands at the alert thresholds (80, 95), not a scale relative to the
  highest score present.
- #34: the About text on the Environment Overview is short and its box
  one row taller, so it no longer runs under the EDIT link.

The visual result still needs a look on devel; this pins the YAML.
Standard library only (line parsing, like the other guards).
Run from the repo root:  python3 tests/test_build95_dashboards.py
"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
KINDS = ["Host", "VM", "Cluster", "vDS", "Portgroup"]


def read(rel):
    return (REPO / rel).read_text(encoding="utf-8")


def columns(text):
    return re.findall(r"^  - attribute:\s*(.+?)\s*$", text, re.M)


def widget(text, wid):
    """The text of one widget item, from its id line to the next item."""
    m = re.search(r"^  - id: %s\n(.*?)(?=^  - id: |^interactions:|\Z)"
                  % re.escape(wid), text, re.M | re.S)
    return m.group(1) if m else None


def coords(block):
    m = re.search(r"coords:\s*\{x:\s*(\d+),\s*y:\s*(\d+),\s*w:\s*(\d+),"
                  r"\s*h:\s*(\d+)\}", block)
    return tuple(int(x) for x in m.groups())


class Build95DashboardTest(unittest.TestCase):

    def test_unmatched_columns(self):
        text = read("views/compliance-by-vcenter.yaml")
        cols = columns(text)
        summed = [int(x) for x in re.search(
            r"^  columns:\s*\[([^\]]*)\]", text, re.M).group(1).split(",")]
        for kind in KINDS:
            key = "VCF-CF Compliance|Rollup|%s|unmatched" % kind
            self.assertIn(key, cols, kind)
            i = cols.index(key)
            self.assertEqual(cols[i - 1],
                             "VCF-CF Compliance|Rollup|%s|non_compliant" % kind,
                             "%s unmatched sits beside non-compliant" % kind)
            self.assertIn(i, summed, "%s unmatched in the totals" % kind)
            self.assertIn('display_name: "%s Not in VCF Ops"' % kind, text)

    def test_scg_versions_newest_first(self):
        cols = columns(read("views/compliance-scg-versions.yaml"))
        want = ["SCG_9.1", "SCG_9.0", "SCG_8.0", "SCG_7.0", "SCG_6.7",
                "none", "unknown"]
        self.assertEqual(
            cols, ["VCF-CF Compliance|Rollup|Benchmark|%s|objects" % b
                   for b in want])
        for name in ["compliance-environment-overview.yaml",
                     "compliance-world-summary.yaml"]:
            with self.subTest(dashboard=name):
                block = widget(read("dashboards/" + name), "scg_version_view")
                x, y, w, h = coords(block)
                self.assertEqual((x, w), (1, 12), "full width")

    def test_heatmap_fixed_scale(self):
        block = widget(read("dashboards/compliance-esxi-hosts.yaml"),
                       "host_score_heatmap")
        self.assertRegex(block, r"min_value:\s*0\b")
        self.assertRegex(block, r"max_value:\s*100\b")
        self.assertRegex(block, r"values:\s*\[0,\s*80,\s*95\]")
        self.assertRegex(block, r"solid_coloring:\s*true")

    def test_about_text_fits(self):
        text = read("dashboards/compliance-environment-overview.yaml")
        block = widget(text, "about_text")
        x, y, w, h = coords(block)
        self.assertGreaterEqual(h, 5)
        body = re.search(r"text: >\n((?:      .*\n)+)", block).group(1)
        words = len(re.sub(r"<[^>]+>", " ", body).split())
        self.assertLessEqual(words, 45, "About text stays short")
        # Nothing overlaps: the next row starts below the first row.
        _, vy, _, _ = coords(widget(text, "vcenter_object_type_view"))
        self.assertGreaterEqual(vy, y + h)

    def test_no_overlap(self):
        for name in ["compliance-environment-overview.yaml",
                     "compliance-world-summary.yaml"]:
            text = read("dashboards/" + name)
            boxes = []
            for wid in re.findall(r"^  - id: (\S+)", text, re.M):
                block = widget(text, wid)
                if block and "coords:" in block:
                    boxes.append((wid, coords(block)))
            for i, (a, (ax, ay, aw, ah)) in enumerate(boxes):
                for b, (bx, by, bw, bh) in boxes[i + 1:]:
                    overlap = (ax < bx + bw and bx < ax + aw
                               and ay < by + bh and by < ay + ah)
                    self.assertFalse(overlap, "%s: %s overlaps %s"
                                     % (name, a, b))


if __name__ == "__main__":
    unittest.main(verbosity=1)
