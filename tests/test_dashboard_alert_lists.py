#!/usr/bin/env python3
"""Drift check: dashboard AlertList widgets vs the generated alerts.

Build 62 (review W1 on build 61). The per-control alert definitions are
generated from the canonical profiles by scripts/generate_compliance_alerts.py;
the dashboards' AlertList widgets name them explicitly. Content authors own
the dashboard YAML, so the generator never rewrites it. This test fails
instead when the two drift apart: a missing, extra or duplicate id in any
dashboard's alert_definitions list.

Expected per dashboard (Ops resource kinds of the generated alerts):
  compliance-environment-overview.yaml  every generated alert (144)
  compliance-esxi-hosts.yaml            HostSystem (esx.*)
  compliance-vms.yaml                   VirtualMachine (vm.*)
  compliance-vcenter-networking.yaml    VMwareAdapter Instance, Cluster,
                                        vDS, portgroup (vc/cluster/vds/dvpg)

Standard library only (the hosted PR workflow installs nothing), so the
alert_definitions lists are read with a small line parser, not PyYAML.

Run from the repo root:  python3 tests/test_dashboard_alert_lists.py
"""

import re
import sys
import unittest
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import generate_compliance_alerts as gen  # noqa: E402

PREFIX = "AlertDefinition-vcfcf_compliance-"

EXPECTED_KINDS = {
    "compliance-environment-overview.yaml": None,   # all kinds
    "compliance-esxi-hosts.yaml": {"HostSystem"},
    "compliance-vms.yaml": {"VirtualMachine"},
    "compliance-vcenter-networking.yaml": {
        "VCenterAdapterInstance", "ClusterComputeResource",
        "DistributedVirtualSwitch", "DistributedVirtualPortgroup"},
}

_ITEM = re.compile(r"""^\s*-\s*["']?([^"'#\s]+)["']?\s*(#.*)?$""")


def alert_lists(path: Path) -> list:
    """Every alert_definitions list in a dashboard YAML, in file order."""
    lists = []
    current = None
    indent = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if current is None:
            if re.match(r"^\s*alert_definitions:\s*$", line):
                current = []
                indent = len(line) - len(line.lstrip())
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _ITEM.match(line)
        if m and (len(line) - len(line.lstrip())) >= indent:
            current.append(m.group(1))
            continue
        lists.append(current)
        current = None
        if re.match(r"^\s*alert_definitions:\s*$", line):
            current = []
            indent = len(line) - len(line.lstrip())
    if current is not None:
        lists.append(current)
    return lists


def expected_ids(kinds) -> list:
    out = []
    for c in gen.collect():
        if kinds is None or c["resource_kind"] in kinds:
            out.append(PREFIX + "vcfcf_compliance_ctl_" + c["slug"])
    return sorted(out)


def diff(actual: list, expected: list) -> list:
    """Human-readable problems: duplicates, missing, extra."""
    problems = []
    dup = sorted(i for i, n in Counter(actual).items() if n > 1)
    if dup:
        problems.append(f"duplicate: {dup}")
    missing = sorted(set(expected) - set(actual))
    if missing:
        problems.append(f"missing: {missing}")
    extra = sorted(set(actual) - set(expected))
    if extra:
        problems.append(f"extra: {extra}")
    return problems


class DashboardAlertListTest(unittest.TestCase):

    def test_dashboards_match_generated_alerts(self):
        for name, kinds in EXPECTED_KINDS.items():
            with self.subTest(dashboard=name):
                lists = alert_lists(REPO / "dashboards" / name)
                self.assertEqual(len(lists), 1,
                                 f"{name}: expected one alert_definitions "
                                 f"list, found {len(lists)}")
                problems = diff(lists[0], expected_ids(kinds))
                self.assertEqual(problems, [], f"{name}: " + "; ".join(problems))

    def test_expected_counts(self):
        # The counts the review recorded for build 61.
        self.assertEqual(len(expected_ids(None)), 144)
        self.assertEqual(len(expected_ids({"HostSystem"})), 86)
        self.assertEqual(len(expected_ids({"VirtualMachine"})), 23)
        self.assertEqual(len(expected_ids(
            EXPECTED_KINDS["compliance-vcenter-networking.yaml"])), 35)

    def test_parser_and_diff_catch_drift(self):
        # The checker itself must fail on each kind of drift.
        exp = ["A-1", "A-2", "A-3"]
        self.assertEqual(diff(["A-1", "A-2", "A-3"], exp), [])
        self.assertIn("missing: ['A-3']", diff(["A-1", "A-2"], exp))
        self.assertIn("extra: ['A-9']", diff(["A-1", "A-2", "A-3", "A-9"], exp))
        self.assertIn("duplicate: ['A-2']",
                      diff(["A-1", "A-2", "A-2", "A-3"], exp))
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "dashboard.yaml"
            sample.write_text(
                "widgets:\n"
                "  - type: AlertList\n"
                "    alert_definitions:\n"
                "        - \"A-1\"\n"
                "        - 'A-2'   # comment\n"
                "\n"
                "        - A-3\n"
                "    title: x\n", encoding="utf-8")
            self.assertEqual(alert_lists(sample), [["A-1", "A-2", "A-3"]])

            # A real dashboard with one id dropped and one duplicated fails.
            real = (REPO / "dashboards" / "compliance-vms.yaml").read_text(
                encoding="utf-8").splitlines(keepends=True)
            items = [i for i, l in enumerate(real) if PREFIX in l]
            mutated = list(real)
            mutated[items[1]] = real[items[0]]        # drop #2, duplicate #1
            bad = Path(tmp) / "vms.yaml"
            bad.write_text("".join(mutated), encoding="utf-8")
            problems = diff(alert_lists(bad)[0],
                            expected_ids({"VirtualMachine"}))
            self.assertTrue(any(x.startswith("missing") for x in problems))
            self.assertTrue(any(x.startswith("duplicate") for x in problems))


if __name__ == "__main__":
    unittest.main(verbosity=1)
