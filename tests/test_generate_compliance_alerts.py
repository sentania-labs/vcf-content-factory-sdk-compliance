#!/usr/bin/env python3
"""Tests for scripts/generate_compliance_alerts.py (stdlib unittest).

Run from the repo root:  python3 tests/test_generate_compliance_alerts.py
"""

import csv
import re
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import generate_compliance_alerts as gen  # noqa: E402

NS = "{http://schemas.vmware.com/vcops/schema}"
OPS_KINDS = {"HostSystem", "VirtualMachine", "VMwareAdapter Instance",
             "ClusterComputeResource", "VmwareDistributedVirtualSwitch",
             "DistributedVirtualPortgroup"}


def properties():
    out = {}
    for line in (REPO / "resources" / "resources.properties").read_text(
            encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v
    return out


class GeneratorTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.controls = gen.collect()
        cls.root = ET.parse(REPO / "describe.xml").getroot()
        cls.props = properties()

    def test_deterministic(self):
        a = gen.render(gen.collect())
        b = gen.render(gen.collect())
        self.assertEqual(a, b)

    def test_committed_output_is_current(self):
        self.assertEqual(gen.main(["gen", "--check"]), 0)

    def test_one_symptom_alert_recommendation_per_control(self):
        n = len(self.controls)
        syms = [s for s in self.root.iter(NS + "SymptomDefinition")
                if s.get("id").startswith("vcfcf_compliance_ctl_")]
        alerts = [a for a in self.root.iter(NS + "AlertDefinition")
                  if a.get("id").startswith("vcfcf_compliance_ctl_")]
        recs = [r for r in self.root.iter(NS + "Recommendation")
                if (r.get("key") or "").startswith("vcfcf_compliance_ctl_")]
        self.assertEqual((len(syms), len(alerts), len(recs)), (n, n, n))
        self.assertEqual(n, 144)

    def test_alert_shape(self):
        for a in self.root.iter(NS + "AlertDefinition"):
            self.assertEqual(a.get("type"), "15")
            self.assertEqual(a.get("subType"), "21", a.get("id"))
            self.assertEqual(a.get("adapterKind"), "VMWARE")
            self.assertIn(a.get("resourceKind"), OPS_KINDS)
            impact = a.find(NS + "State/" + NS + "Impact")
            self.assertEqual((impact.get("type"), impact.get("key")),
                             ("badge", "risk"))

    def test_alert_names_are_id_colon_title(self):
        by_id = {c["control_id"]: c for c in self.controls}
        for a in self.root.iter(NS + "AlertDefinition"):
            if not a.get("id").startswith("vcfcf_compliance_ctl_"):
                continue
            name = self.props[a.get("nameKey")]
            cid, sep, title = name.partition(": ")
            self.assertEqual(sep, ": ", name)
            self.assertIn(cid, by_id)
            self.assertEqual(title, by_id[cid]["title"])

    def test_symptom_condition(self):
        for s in self.root.iter(NS + "SymptomDefinition"):
            if not s.get("id").startswith("vcfcf_compliance_ctl_"):
                continue
            state = s.find(NS + "State")
            self.assertIn(state.get("severity"),
                          {"Critical", "Immediate", "Warning"})
            cond = state.find(NS + "Condition")
            self.assertEqual(cond.get("type"), "metric")
            self.assertEqual((cond.get("operator"), cond.get("value")),
                             ("=", "0"))
            self.assertRegex(cond.get("key"),
                             r"^VCF-CF Compliance\|[a-z]+\.[a-z0-9-]+\|Compliant$")

    def test_every_namekey_resolves(self):
        for el in self.root.iter():
            nk = el.get("nameKey")
            if nk is not None:
                self.assertIn(nk, self.props, f"nameKey {nk} unresolved")

    def test_properties_ascii(self):
        for k, v in self.props.items():
            if int(k.split(".")[0]) >= gen.NAMEKEY_BASE:
                v.encode("ascii")

    def test_manual_review_only_controls_not_alerted(self):
        ids = {c["control_id"] for c in self.controls}
        # Prose-expected in every profile that carries them.
        for cid in ("esx.etc-issue", "vc.etc-issue", "esx.login-message",
                    "esx.log-forwarding", "esx.ad-admin-group-name",
                    "esx.logs-remote", "esx.annotations-welcomemessage"):
            self.assertNotIn(cid, ids)
        # Scored again in build 57 (vmx minimum).
        self.assertIn("vm.virtual-hardware", ids)

    def test_severity_from_priority(self):
        for c in self.controls:
            self.assertIn(c["priority"], gen.SEVERITY)

    def test_existing_score_alert_is_compliance_subtype(self):
        a = [x for x in self.root.iter(NS + "AlertDefinition")
             if x.get("id") == "vcfcf_compliance_score_degraded"][0]
        self.assertEqual(a.get("subType"), "21")

    def test_scored_rule_matches_manual_review_file(self):
        manual = gen.load_manual_review()
        with (REPO / "profiles" / "manual_review.csv").open(
                encoding="utf-8", newline="") as f:
            self.assertEqual(len(list(csv.DictReader(f))), len(manual))


if __name__ == "__main__":
    unittest.main(verbosity=1)
