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
- Scott's decision 2026-10-14 (point 4): an "Objects with Unreadable
  Controls" list (object, kind, count, reason; the list view filtered on
  has_unreadable = 1 over the six kinds) sits next to the Controls
  Passing tile on the Environment Overview and the World Summary.
- Review B2: Not Fully Read (has_unreadable) sits directly beside the
  score in the six per-kind views (summed in the totals row) and in the
  ESX Hosts host details, so a score kept from an earlier cycle is never
  shown without its tell; no view description still names "Controls
  Evaluated = 0" as the tell.

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

    def test_unreadable_list(self):
        view_name = ("[VCF Content Factory] Compliance Objects with "
                     "Unreadable Controls")
        text = read("views/compliance-unreadable-objects.yaml")
        self.assertIn('name: "%s"' % view_name, text)
        kinds = re.findall(r"^    resource_kind:\s*(.+?)\s*$", text, re.M)
        self.assertEqual(kinds, [
            "HostSystem", "VirtualMachine", "VMwareAdapter Instance",
            "ClusterComputeResource", "VmwareDistributedVirtualSwitch",
            "DistributedVirtualPortgroup"])
        flt = re.search(r"^  filter:\n((?:    .*\n)+)", text, re.M).group(1)
        self.assertIn('metric_key: "VCF-CF Compliance|has_unreadable"', flt)
        self.assertRegex(flt, r"condition:\s*EQUALS")
        self.assertRegex(flt, r"value:\s*1\b")
        self.assertEqual(columns(text), [
            "VCF-CF Compliance|object_kind",
            "VCF-CF Compliance|unreadable_count",
            "VCF-CF Compliance|unreadable_reason"])
        self.assertIn("views/compliance-unreadable-objects.yaml",
                      read("adapter.yaml"))
        for name in ["compliance-environment-overview.yaml",
                     "compliance-world-summary.yaml"]:
            with self.subTest(dashboard=name):
                dash = read("dashboards/" + name)
                block = widget(dash, "unreadable_objects_view")
                self.assertIsNotNone(block, "list widget present")
                self.assertRegex(block, r"type:\s*View")
                self.assertIn('view: "%s"' % view_name, block)
                x, y, w, h = coords(block)
                sx, sy, sw, sh = coords(widget(dash,
                                               "env_compliance_scoreboard"))
                self.assertEqual(y, sy, "same row as the scoreboard")
                self.assertEqual(x, sx + sw, "directly right of the tile")
                self.assertGreaterEqual(w, 5, "wide enough for the reason")

    def test_flag_beside_score(self):
        flag = "VCF-CF Compliance|has_unreadable"
        for name in ["host-detail", "vm-detail", "vcenter-list",
                     "cluster-list", "vds-list", "portgroup-list"]:
            with self.subTest(view=name):
                text = read("views/compliance-%s.yaml" % name)
                cols = columns(text)
                i = cols.index("VCF-CF Compliance|score")
                self.assertEqual(cols[i + 1], flag)
                summed = [int(x) for x in re.search(
                    r"^  columns:\s*\[([^\]]*)\]", text, re.M
                ).group(1).split(",")]
                self.assertIn(i + 1, summed)
                self.assertNotIn("score", [cols[k].split("|")[-1]
                                           for k in summed])
                self.assertNotIn("Controls Evaluated = 0", text)
                self.assertIn("Not Fully Read", text)
        block = widget(read("dashboards/compliance-esxi-hosts.yaml"),
                       "host_compliance_details")
        self.assertIn('metric_key: "%s"' % flag, block)

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
