#!/usr/bin/env python3
"""Build 93: the account dialog is Host, Credential, Collector, and under
Advanced Settings the overrides file and the appliance read (stdlib
unittest).

An identifier lands under Advanced Settings when it has identType="2" and
is required="false" or carries a default (VCF Ops 9.0.2 controller rule,
factory investigation 2026-10-13-account-dialog-advanced-settings-and-
cert-accept.md). benchmark_profile and allowInsecure are removed and their
nameKeys retired.

Run from the repo root:  python3 tests/test_describe_account_dialog.py
"""

import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
NS = "{http://schemas.vmware.com/vcops/schema}"


class AccountDialogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = ET.parse(REPO / "describe.xml").getroot()
        kind = next(k for k in root.iter(NS + "ResourceKind")
                    if k.get("key") == "vcfcf_compliance")
        cls.idents = {i.get("key"): i
                      for i in kind.findall(NS + "ResourceIdentifier")}
        cls.props = (REPO / "resources" / "resources.properties").read_text(
            encoding="utf-8")

    def test_exact_identifier_set(self):
        self.assertEqual(
            set(self.idents),
            {"vcenter_host", "overrides_file", "read_appliance_settings"})

    def test_host_is_main_form(self):
        host = self.idents["vcenter_host"]
        self.assertIsNone(host.get("identType"))
        self.assertEqual(host.get("required"), "true")

    def test_advanced_fields(self):
        for key in ("overrides_file", "read_appliance_settings"):
            i = self.idents[key]
            self.assertEqual(i.get("identType"), "2", key)
            self.assertEqual(i.get("required"), "false", key)
            self.assertIsNone(i.get("hidden"), key)

    def test_read_appliance_is_true_false_enum(self):
        i = self.idents["read_appliance_settings"]
        self.assertEqual(i.get("enum"), "true")
        self.assertEqual(i.get("default"), "false")
        self.assertEqual([e.get("value") for e in i.findall(NS + "enum")],
                         ["false", "true"])

    def test_retired_name_keys(self):
        for n in ("7", "8", "9"):
            self.assertIsNone(re.search(r"^%s=" % n, self.props, re.M), n)


if __name__ == "__main__":
    unittest.main()
