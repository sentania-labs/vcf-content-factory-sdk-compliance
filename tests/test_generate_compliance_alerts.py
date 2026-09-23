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
        # build 70: 6 standard-switch controls removed; build 72:
        # vds.network-reset-port folded into dvpg.network-reset-port
        self.assertEqual(n, 136)   # build 74: cluster.object-checksum demoted

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

    def test_standard_switch_controls_not_alerted(self):
        # Build 70 (Codex P1): host-side standard-switch controls were read
        # from the distributed switch; they are no longer scored or alerted.
        ids = {c["control_id"] for c in self.controls}
        # Build 72: reset-port is a portgroup control in every profile.
        self.assertNotIn("vds.network-reset-port", ids)
        rp = [c for c in self.controls if c["control_id"] == "dvpg.network-reset-port"]
        self.assertEqual(len(rp), 1)
        self.assertEqual(rp[0]["resource_kind"], "DistributedVirtualPortgroup")
        self.assertEqual(rp[0]["labels"], ["SCG 7.0", "SCG 8.0", "SCG 9.0", "SCG 9.1"])
        for cid in ("vds.network-reject-forged-transmit-standardswitch",
                    "vds.network-reject-mac-changes-standardswitch",
                    "vds.network-reject-promiscuous-mode-standardswitch",
                    "vds.network-standard-reject-forged-transmit",
                    "vds.network-standard-reject-mac-changes",
                    "vds.network-standard-reject-promiscuous-mode"):
            self.assertNotIn(cid, ids)

    def test_manual_review_only_controls_not_alerted(self):
        ids = {c["control_id"] for c in self.controls}
        # Prose-expected in every profile that carries them.
        for cid in ("esx.etc-issue", "vc.etc-issue", "esx.login-message",
                    "esx.log-forwarding", "esx.ad-admin-group-name",
                    "esx.logs-remote", "esx.annotations-welcomemessage"):
            self.assertNotIn(cid, ids)
        # Scored again in build 57 (vmx minimum).
        self.assertIn("vm.virtual-hardware", ids)

    def test_collection_alerts(self):
        # Build 63: one "Compliance data not collected" alert per kind.
        ids = gen.collection_ids()
        self.assertEqual(len(ids), 6)
        alerts = {a.get("id"): a for a in self.root.iter(NS + "AlertDefinition")}
        syms = {s.get("id"): s for s in self.root.iter(NS + "SymptomDefinition")}
        ops_kinds = set()
        for _kind, ops_kind, sid, aid, label in ids:
            self.assertTrue(aid.startswith("vcfcf_compliance_collection_"))
            self.assertFalse(aid.startswith("vcfcf_compliance_ctl_"))
            a = alerts[aid]
            self.assertEqual((a.get("type"), a.get("subType")), ("15", "21"))
            self.assertEqual(a.get("resourceKind"), ops_kind)
            ops_kinds.add(ops_kind)
            self.assertEqual(self.props[a.get("nameKey")],
                             f"Compliance data not collected ({label})")
            rec = a.find(NS + "State/" + NS + "Recommendations/"
                         + NS + "Recommendation")
            self.assertEqual(rec.get("ref"), gen.COLLECTION_REC_ID)
            sym = syms[sid]
            state = sym.find(NS + "State")
            self.assertEqual(state.get("severity"), "Immediate")
            cond = state.find(NS + "Condition")
            self.assertEqual((cond.get("type"), cond.get("key"),
                              cond.get("operator"), cond.get("value")),
                             ("metric", "VCF-CF Compliance|unreadable_count",
                              ">", "0"))
            # Build 65: OR collection_failed = 1, via a two-child
            # SymptomSets (a bare-sibling list would drop all but one).
            fsid = gen.collection_failed_symptom_id(sid)
            fstate = syms[fsid].find(NS + "State")
            self.assertEqual(fstate.get("severity"), "Immediate")
            fcond = fstate.find(NS + "Condition")
            self.assertEqual((fcond.get("type"), fcond.get("key"),
                              fcond.get("operator"), fcond.get("value")),
                             ("metric", "VCF-CF Compliance|collection_failed",
                              "=", "1"))
            sets = a.find(NS + "State/" + NS + "SymptomSets")
            self.assertEqual(sets.get("operator"), "or")
            self.assertEqual([x.get("ref") for x in
                              sets.findall(NS + "SymptomSet")], [sid, fsid])
        self.assertEqual(ops_kinds, OPS_KINDS)
        recs = [r for r in self.root.iter(NS + "Recommendation")
                if r.get("key") == gen.COLLECTION_REC_ID]
        self.assertEqual(len(recs), 1)
        text = self.props[recs[0].find(NS + "Description").get("nameKey")]
        for needle in ("unreadable_count", "-1", "permission", "disconnected",
                       "not supported", "SystemConfiguration.Administrators",
                       "WRITE access"):
            self.assertIn(needle, text)

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
