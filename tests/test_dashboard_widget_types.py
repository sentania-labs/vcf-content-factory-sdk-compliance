"""Guard: bundled dashboards use only widget types proven on 9.0.x.

Why: the VCF Operations 9.0.x content importer has no Section widget
type. A dashboard carrying one aborts the import of that whole dashboard
(JSONObject["Title"] not found in the server log), while the pak install
still reports success. That is how the build 88 Compliance World Summary
dashboard never imported and the ComplianceWorld Summary tab never bound
on devel; build 89 dropped the Section row. Nothing in validate-sdk,
pak-compare or the other tests caught it (build 89 review, WARNING 1).

So every widget in every dashboard YAML under dashboards/ must have a
type in ALLOWED_WIDGET_TYPES, the types in use when 89 imported cleanly.
Extending the allowlist needs proof that the new type imports on the
oldest targeted VCF Operations version (9.0.x today): a dashboard using
it installed there and seen rendering, not just a green install.

Standard library only (the hosted PR workflow installs nothing), so the
widgets are read with the same small line parser approach as
test_dashboard_alert_lists.py, not PyYAML.

Run from the repo root:  python3 tests/test_dashboard_widget_types.py
"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

ALLOWED_WIDGET_TYPES = frozenset({
    "Scoreboard", "PropertyList", "View", "MetricChart", "AlertList",
    "ResourceList", "Heatmap", "TextDisplay",
})

_TOP_LEVEL = re.compile(r"^(\S[^:]*):")
_ITEM_START = re.compile(r"^  - ")
_KEY = re.compile(r"^(?:  - |    )(id|type):\s*(.*?)\s*$")


def widgets(text: str) -> list:
    """Every item under the top-level `widgets:` key, in file order, as
    a dict: id, types (every `type:` value found at the widget's own
    level, so a missing or duplicated type is visible)."""
    out = []
    cur = None
    in_widgets = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        top = _TOP_LEVEL.match(line)
        if top:
            in_widgets = top.group(1) == "widgets"
            cur = None
            continue
        if not in_widgets:
            continue
        if _ITEM_START.match(line):
            cur = {"id": None, "types": []}
            out.append(cur)
        if cur is None:
            continue
        m = _KEY.match(line)
        if m:
            value = m.group(2).strip("'\"")
            if m.group(1) == "id":
                cur["id"] = value
            else:
                cur["types"].append(value)
    return out


def type_problems(name: str, text: str) -> list:
    """Human-readable violations for one dashboard file."""
    problems = []
    for w in widgets(text):
        wid = w["id"] or "<no id>"
        if len(w["types"]) != 1:
            problems.append(f"{name}: widget {wid} has {len(w['types'])} "
                            f"type lines {w['types']}, expected exactly one")
            continue
        wtype = w["types"][0]
        if wtype not in ALLOWED_WIDGET_TYPES:
            problems.append(
                f"{name}: widget {wid} has type {wtype}, which is not in the "
                f"allowlist of widget types proven to import on VCF "
                f"Operations 9.0.x {sorted(ALLOWED_WIDGET_TYPES)}")
    return problems


class DashboardWidgetTypeTest(unittest.TestCase):

    def test_every_widget_type_is_allowed(self):
        paths = sorted((REPO / "dashboards").glob("*.yaml"))
        self.assertTrue(paths, "no dashboard YAML found under dashboards/")
        for path in paths:
            with self.subTest(dashboard=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertTrue(widgets(text),
                                f"{path.name}: parser found no widgets")
                problems = type_problems(path.name, text)
                self.assertEqual(problems, [], "; ".join(problems))

    def test_checker_catches_disallowed_type(self):
        # The checker itself must fail on a Section widget, on a missing
        # type, and must ignore interaction `type:` lines.
        name = "compliance-world-summary.yaml"
        real = (REPO / "dashboards" / name).read_text(encoding="utf-8")
        self.assertEqual(type_problems(name, real), [])

        section = real.replace(
            "widgets:\n",
            "widgets:\n  - id: header_row\n    type: Section\n"
            "    title: Compliance Environment\n", 1)
        problems = type_problems(name, section)
        self.assertEqual(len(problems), 1)
        self.assertIn("header_row", problems[0])
        self.assertIn(name, problems[0])
        self.assertIn("widget types proven to import on VCF Operations "
                      "9.0.x", problems[0])

        # type as the first key of the item is still seen
        first_key = "widgets:\n  - type: Section\n    id: hdr\n"
        self.assertTrue(any("hdr" in p for p in
                            type_problems("x.yaml", first_key)))
        # a widget with no type line fails
        self.assertTrue(type_problems(
            "x.yaml", "widgets:\n  - id: a\n    title: t\n"))
        # a commented-out type does not count
        self.assertTrue(type_problems(
            "x.yaml", "widgets:\n  - id: a\n    # type: View\n"))
        # interaction types are outside widgets: and are not checked
        self.assertEqual(type_problems(
            "x.yaml", "widgets:\n  - id: a\n    type: View\n"
            "interactions:\n  - from: a\n    to: b\n    type: resourceId\n"),
            [])


if __name__ == "__main__":
    unittest.main(verbosity=1)
