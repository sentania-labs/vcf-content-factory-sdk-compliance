#!/usr/bin/env python3
"""Structural gate on describe.xml composite symptom sets (stdlib unittest).

VCF Operations rejects the whole describe at install when any
<SymptomSets> container has fewer than two children: "A composite symptom
set should contain at least two Symptom Sets/Composite Symptom Sets". The
build 90 overrides alert hit this; validate-sdk, review and pak-compare
did not catch it (factory issues #202, #203). A single symptom set goes
bare under <State>, never in a composite container.

Run from the repo root:  python3 tests/test_describe_symptom_sets.py
"""

import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
NS = "{http://schemas.vmware.com/vcops/schema}"
CHILD_TAGS = {NS + "SymptomSet", NS + "SymptomSets"}


def undersized(root):
    """Every <SymptomSets> anywhere in the describe with fewer than two set
    children, as (enclosing alert id or None, child count). Scans the whole
    tree, not just AlertDefinitions, so a container in any section fails."""
    parent = {c: p for p in root.iter() for c in p}
    out = []
    for sets in root.iter(NS + "SymptomSets"):
        n = sum(1 for c in sets if c.tag in CHILD_TAGS)
        if n < 2:
            alert, node = None, sets
            while node in parent:
                node = parent[node]
                if node.tag == NS + "AlertDefinition":
                    alert = node.get("id")
                    break
            out.append((alert, n))
    return out


class DescribeSymptomSetsTest(unittest.TestCase):

    def test_no_composite_with_fewer_than_two_children(self):
        root = ET.parse(REPO / "describe.xml").getroot()
        self.assertTrue(any(True for _ in root.iter(NS + "AlertDefinition")))
        self.assertEqual(undersized(root), [])

    def test_detector_catches_one_child_composite(self):
        # Guard the guard: a one-child and an empty container both flag,
        # a two-child one and a nested two-child one do not, and a container
        # outside any AlertDefinition still flags (alert id None).
        xml = (
            f'<r xmlns="{NS[1:-1]}">'
            '<AlertDefinition id="one"><State><SymptomSets operator="or">'
            '<SymptomSet ref="a"/></SymptomSets></State></AlertDefinition>'
            '<AlertDefinition id="empty"><State><SymptomSets operator="or"/>'
            '</State></AlertDefinition>'
            '<AlertDefinition id="two"><State><SymptomSets operator="or">'
            '<SymptomSet ref="a"/><SymptomSet ref="b"/></SymptomSets>'
            '</State></AlertDefinition>'
            '<AlertDefinition id="nested"><State><SymptomSets operator="and">'
            '<SymptomSet ref="a"/><SymptomSets operator="or">'
            '<SymptomSet ref="b"/></SymptomSets></SymptomSets>'
            '</State></AlertDefinition>'
            '<Other><SymptomSets operator="or"><SymptomSet ref="c"/>'
            '</SymptomSets></Other>'
            '</r>')
        self.assertEqual(undersized(ET.fromstring(xml)),
                         [("one", 1), ("empty", 0), ("nested", 1),
                          (None, 1)])


if __name__ == "__main__":
    unittest.main(verbosity=1)
