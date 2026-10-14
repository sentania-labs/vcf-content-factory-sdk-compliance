"""Guard: build 95 percentages are bound to the pass-rate keys.

Why: build 95 (Scott 2026-10-14, "compliance percentage is basically:
Total passing controls/total controls evaluated") replaced every shown
object-mean percentage (Rollup|<Kind>|avg_score, Rollup|Environment|
avg_score) with controls passed over controls evaluated
(Rollup|<Kind>|pass_rate, Rollup|Environment|pass_rate). The avg_score
keys are still pushed, so a dashboard or view left on them renders a
plausible but different number with no error. This test pins:

- no bundled dashboard or view binds an avg_score key;
- the Environment Compliance tile and the trend chart on both the
  Environment Overview and the Compliance World Summary read
  Rollup|Environment|pass_rate, labelled Controls Passing;
- the per-vCenter view has a "<Kind> Controls Passing (%)" column bound
  to Rollup|<Kind>|pass_rate for every kind, a Controls Unreadable (All)
  column, and a totals row that sums counts, never a percentage.

Standard library only, line-based (no PyYAML), like the other guards.
Run from the repo root:  python3 tests/test_pass_rate_bindings.py
"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
KINDS = ["Host", "VM", "Cluster", "vDS", "Portgroup", "vCenter"]
ENV_DASHBOARDS = ["compliance-environment-overview.yaml",
                  "compliance-world-summary.yaml"]


def bundled(section: str) -> list:
    """Paths listed under bundled_content.<section> in adapter.yaml."""
    out, inside = [], False
    for line in (REPO / "adapter.yaml").read_text().splitlines():
        if re.match(r"^  %s:\s*$" % section, line):
            inside = True
            continue
        if inside:
            m = re.match(r"^    - (\S+)", line)
            if m:
                out.append(m.group(1))
            elif line.strip() and not line.lstrip().startswith("#"):
                inside = False
    return out


def code(text: str) -> str:
    """The text with comments removed."""
    return "\n".join(l.split("#", 1)[0] for l in text.splitlines())


def view_columns(text: str) -> list:
    """(attribute, display_name) for each column, in order."""
    cols = []
    for line in text.splitlines():
        m = re.match(r"^  - attribute:\s*(.+?)\s*$", line)
        if m:
            cols.append([m.group(1), None])
            continue
        m = re.match(r'^    display_name:\s*"(.*)"\s*$', line)
        if m and cols and cols[-1][1] is None:
            cols[-1][1] = m.group(1)
    return [tuple(c) for c in cols]


class PassRateBindingTest(unittest.TestCase):

    def test_bundled_content_has_no_avg_score(self):
        paths = bundled("views") + bundled("dashboards")
        self.assertTrue(paths, "no bundled content found in adapter.yaml")
        for rel in paths:
            with self.subTest(path=rel):
                text = code((REPO / rel).read_text(encoding="utf-8"))
                self.assertNotIn("avg_score", text)

    def test_environment_tile_and_trend(self):
        for name in ENV_DASHBOARDS:
            with self.subTest(dashboard=name):
                text = code((REPO / "dashboards" / name).read_text())
                keys = re.findall(
                    r'metric_key:\s*"Rollup\|Environment\|pass_rate"\s*\n'
                    r'\s*metric_name:\s*"Controls Passing"', text)
                # one in the Environment Compliance scoreboard, one in the
                # trend chart
                self.assertEqual(len(keys), 2, name)
                self.assertIn('label: "Controls Passing"', text)

    def test_vcenter_view_columns(self):
        text = (REPO / "views" / "compliance-by-vcenter.yaml").read_text()
        cols = view_columns(text)
        attrs = [a for a, _ in cols]
        for kind in KINDS:
            want = ("VCF-CF Compliance|Rollup|%s|pass_rate" % kind,
                    "%s Controls Passing (%%)" % kind)
            self.assertIn(want, cols, kind)
        self.assertIn(("VCF-CF Compliance|Rollup|All|controls_unreadable",
                       "Controls Unreadable"), cols)
        m = re.search(r"^  columns:\s*\[([^\]]*)\]", text, re.M)
        self.assertIsNotNone(m, "summary columns")
        summed = [int(x) for x in m.group(1).split(",")]
        for i in summed:
            self.assertLess(i, len(attrs))
            self.assertFalse(attrs[i].endswith("|pass_rate"),
                             "a percentage is summed: " + attrs[i])
        self.assertIn(
            attrs.index("VCF-CF Compliance|Rollup|All|controls_unreadable"),
            summed, "Controls Unreadable is in the totals row")


if __name__ == "__main__":
    unittest.main(verbosity=1)
