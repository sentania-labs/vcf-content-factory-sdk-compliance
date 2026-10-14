"""Drift check: dashboard AlertList widgets vs the alert contract.

Build 62 pinned each AlertList to an explicit alert_definitions list and
this test compared the lists to the generated alerts. Commit 370f69f
replaced those pins with a type filter: every pak alert is Application /
Compliance (type 15, subType 21), so an AlertList carries
`alert_types: ["15_21"]` and no definition pins, and the per-widget
`depth` says how many descendant levels below the input object carry
compliance alerts. Nothing needs regenerating when an alert is added, so
the drift this test guards is now in the widget config:
  - the type filter is present and exactly ["15_21"]
  - no alert_definitions pin has crept back in
  - depth matches the documented per-dashboard value
  - every dashboard has exactly the expected AlertList count

Expected depth per dashboard (see the comment above each depth in the YAML):
  compliance-environment-overview.yaml  4  (vCenter > Datacenter > Cluster
                                            > HostSystem > VirtualMachine)
  compliance-esxi-hosts.yaml            1  (HostSystem > VirtualMachine)
  compliance-vms.yaml                   1  (VirtualMachine)
  compliance-vcenter-networking.yaml    4  (vCenter, cluster, vDS, portgroup)
  compliance-world-summary.yaml         4  (input is the selected vCenter
                                            row: vCenter > Datacenter >
                                            Cluster > HostSystem >
                                            VirtualMachine)

The generator's collection counts are still asserted, since the alert
set itself is what the type filter selects.

Standard library only (the hosted PR workflow installs nothing), so the
AlertList widgets are read with a small line parser, not PyYAML.

Run from the repo root:  python3 tests/test_dashboard_alert_lists.py
"""

import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import generate_compliance_alerts as gen  # noqa: E402

PREFIX = "AlertDefinition-vcfcf_compliance-"

# dashboard file -> (expected AlertList depth, resource kinds of its alerts)
EXPECTED_DEPTH = {
    "compliance-environment-overview.yaml": 4,
    "compliance-esxi-hosts.yaml": 1,
    "compliance-vms.yaml": 1,
    "compliance-vcenter-networking.yaml": 4,
    "compliance-world-summary.yaml": 4,
}

EXPECTED_KINDS = {
    "compliance-vcenter-networking.yaml": {
        "VCenterAdapterInstance", "ClusterComputeResource",
        "DistributedVirtualSwitch", "DistributedVirtualPortgroup"},
}

_WIDGET_START = re.compile(r"^  - id:\s*(\S+)")
_TOP_LEVEL = re.compile(r"^\S")


def alert_widgets(text: str) -> list:
    """Every AlertList widget in a dashboard YAML, in file order, as a
    dict: id, lines (the widget's raw lines)."""
    widgets = []
    cur = None
    for raw in text.splitlines():
        m = _WIDGET_START.match(raw)
        if m or _TOP_LEVEL.match(raw):
            if cur is not None:
                widgets.append(cur)
            cur = {"id": m.group(1), "lines": []} if m else None
            continue
        if cur is not None:
            cur["lines"].append(raw)
    if cur is not None:
        widgets.append(cur)
    return [w for w in widgets
            if any(re.match(r"^    type:\s*AlertList\s*$", l)
                   for l in w["lines"])]


def widget_problems(widget: dict, depth: int) -> list:
    """Human-readable contract violations for one AlertList widget."""
    problems = []
    code = [l.split("#", 1)[0].rstrip() for l in widget["lines"]]
    code = [l for l in code if l.strip()]
    types = [l for l in code if re.match(r"^    alert_types:", l)]
    if len(types) != 1 or re.sub(r"\s+", "", types[0].split(":", 1)[1]) \
            != '["15_21"]':
        problems.append(f"{widget['id']}: alert_types must be exactly "
                        f'["15_21"], found {types}')
    if any(re.match(r"^\s*alert_definitions:", l) for l in code):
        problems.append(f"{widget['id']}: alert_definitions pin present")
    depths = [l for l in code if re.match(r"^    depth:", l)]
    if len(depths) != 1 or depths[0].split(":", 1)[1].strip() != str(depth):
        problems.append(f"{widget['id']}: depth must be {depth}, "
                        f"found {depths}")
    return problems


def coverage_problems(name: str, text: str, covered: set) -> list:
    """Why a dashboard file escapes this test, if it does: an AlertList
    with no expected depth here, or (build 88 review N6) the word AlertList
    in the file while the line parser found no AlertList widget, e.g. a
    widget indented differently from `  - id:` / `    type: AlertList`."""
    problems = []
    widgets = alert_widgets(text)
    if widgets and name not in covered:
        problems.append(f"{name} has an AlertList but no expected depth "
                        f"in this test")
    if not widgets and re.search(r"\bAlertList\b", text):
        problems.append(f"{name} mentions AlertList but the line parser "
                        f"found no AlertList widget; fix the parser or "
                        f"the indentation")
    return problems


def expected_ids(kinds) -> list:
    out = []
    for c in gen.collect():
        if kinds is None or c["resource_kind"] in kinds:
            out.append(PREFIX + "vcfcf_compliance_ctl_" + c["slug"])
    for kind, _ops, _sid, aid, _label in gen.collection_ids():
        if kinds is None or kind in kinds:
            out.append(PREFIX + aid)
    return sorted(out)


class DashboardAlertListTest(unittest.TestCase):

    def test_alert_lists_use_type_filter_and_depth(self):
        for name, depth in EXPECTED_DEPTH.items():
            with self.subTest(dashboard=name):
                text = (REPO / "dashboards" / name).read_text(encoding="utf-8")
                widgets = alert_widgets(text)
                self.assertEqual(len(widgets), 1,
                                 f"{name}: expected one AlertList, "
                                 f"found {len(widgets)}")
                problems = widget_problems(widgets[0], depth)
                self.assertEqual(problems, [], f"{name}: " + "; ".join(problems))

    def test_every_dashboard_is_covered(self):
        # A new dashboard with an AlertList must be added to EXPECTED_DEPTH.
        # compliance-overview.yaml (retired Fleet Overview, unbundled)
        # keeps its own depth 5 and is checked here too.
        covered = set(EXPECTED_DEPTH) | {"compliance-overview.yaml"}
        for path in sorted((REPO / "dashboards").glob("*.yaml")):
            text = path.read_text(encoding="utf-8")
            problems = coverage_problems(path.name, text, covered)
            self.assertEqual(problems, [], "; ".join(problems))

    def test_coverage_check_catches_unparsed_alert_list(self):
        # Build 88 review N6: an AlertList the line parser cannot see must
        # fail the coverage check, not pass it silently.
        real = (REPO / "dashboards" / "compliance-world-summary.yaml"
                ).read_text(encoding="utf-8")
        name = "compliance-world-summary.yaml"
        self.assertEqual(coverage_problems(name, real, {name}), [])
        # uncovered dashboard with a parsed AlertList
        self.assertTrue(coverage_problems(name, real, set()))
        # the same widget indented differently: parser misses it
        shifted = "\n".join("  " + l if l.strip() else l
                            for l in real.splitlines())
        self.assertEqual(alert_widgets(shifted), [])
        self.assertTrue(any("line parser" in p for p in
                            coverage_problems(name, shifted, {name})))
        # no AlertList anywhere: nothing to report
        self.assertEqual(coverage_problems(
            "x.yaml", "widgets:\n  - id: a\n    type: View\n", set()), [])

    def test_retired_fleet_overview_alert_list(self):
        text = (REPO / "dashboards" / "compliance-overview.yaml").read_text(
            encoding="utf-8")
        widgets = alert_widgets(text)
        self.assertEqual(len(widgets), 1)
        self.assertEqual(widget_problems(widgets[0], 5), [])

    def test_expected_counts(self):
        # Build 70: 138 per-control (6 standard-switch vDS controls
        # removed) plus the build-63 collection alert per kind.
        self.assertEqual(len(expected_ids(None)), 142)
        self.assertEqual(len(expected_ids({"HostSystem"})), 87)
        self.assertEqual(len(expected_ids({"VirtualMachine"})), 24)
        self.assertEqual(len(expected_ids(
            EXPECTED_KINDS["compliance-vcenter-networking.yaml"])), 31)

    def test_checker_catches_drift(self):
        # The checker itself must fail on each kind of drift.
        real = (REPO / "dashboards" / "compliance-world-summary.yaml"
                ).read_text(encoding="utf-8")
        good = alert_widgets(real)[0]
        self.assertEqual(widget_problems(good, 4), [])
        self.assertTrue(widget_problems(good, 5))            # wrong depth

        def mutate(old, new):
            return alert_widgets(real.replace(old, new))[0]

        # type filter dropped
        self.assertTrue(any("alert_types" in p for p in widget_problems(
            mutate('    alert_types: ["15_21"]', "    mode_x: 1"), 4)))
        # wrong subtype
        self.assertTrue(any("alert_types" in p for p in widget_problems(
            mutate('["15_21"]', '["15_22"]'), 4)))
        # a definition pin creeps back in
        self.assertTrue(any("alert_definitions" in p for p in widget_problems(
            mutate("    mode: all\n",
                   "    mode: all\n    alert_definitions:\n"
                   "      - AlertDefinition-x\n"), 4)))
        # depth changed
        self.assertTrue(any("depth" in p for p in widget_problems(
            mutate("    depth: 4", "    depth: 1"), 4)))
        # a commented-out filter does not count
        self.assertTrue(any("alert_types" in p for p in widget_problems(
            mutate('    alert_types: ["15_21"]',
                   '    # alert_types: ["15_21"]'), 4)))


if __name__ == "__main__":
    unittest.main(verbosity=1)
