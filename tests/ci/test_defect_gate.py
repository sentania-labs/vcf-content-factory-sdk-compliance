"""Tests for the vendored ci/defect_gate.py (issue #18 CI4).

Stdlib only. Run from the repo root:

    python3 -m unittest discover -s tests/ci -p 'test_*.py' -v

The release workflow runs this before the gate itself.
"""
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ci"))

import defect_gate  # noqa: E402

ENTRY = textwrap.dedent("""\
    {heading}

    - **Title:** something broke
    - **Severity:** {severity}
    - **Status:** open
    - **Affects:** {affects}
    - **First-seen:** build 1 (2026-10-16)
    - **Source:** review
    - **Summary:** it broke
    """)


def registry(*entries: str, preamble: str = "# Defect registry\n\n## Defects\n\n") -> str:
    return preamble + "\n".join(entries)


def entry(n: int, affects: str, severity: str = "blocking", heading: str = None) -> str:
    return ENTRY.format(heading=heading or f"### DEF-{n:03d}",
                        affects=affects, severity=severity)


class GateTest(unittest.TestCase):

    def write(self, text: str) -> Path:
        d = Path(tempfile.mkdtemp())
        p = d / "defects.md"
        p.write_text(text, encoding="utf-8")
        return p

    def run_cli(self, path: Path, pak: str) -> int:
        return subprocess.run(
            [sys.executable, str(ROOT / "ci" / "defect_gate.py"),
             "--pak", pak, "--registry", str(path)],
            capture_output=True, text=True).returncode

    # --- fail closed -----------------------------------------------------

    def test_empty_registry_fails_closed(self):
        p = self.write("")
        with self.assertRaises(defect_gate.DefectRegistryError):
            defect_gate.gate_pak("template", p)
        self.assertEqual(self.run_cli(p, "template"), 1)

    def test_no_def_sections_fails_closed(self):
        # An HTML error page or a reformatted registry: no DEF- sections.
        p = self.write("<html><body>404: Not Found</body></html>\n")
        self.assertEqual(self.run_cli(p, "template"), 1)
        p = self.write("# Defect registry\n\n## Defects\n\n#### Defect 1\n- **Affects:** template\n")
        self.assertEqual(self.run_cli(p, "template"), 1)

    def test_malformed_def_heading_fails_closed(self):
        p = self.write(registry(entry(1, "unifi"),
                                entry(2, "template", heading="### DEF-1O2")))
        with self.assertRaises(defect_gate.DefectRegistryError):
            defect_gate.gate_pak("template", p)
        self.assertEqual(self.run_cli(p, "template"), 1)

    def test_deep_or_odd_def_heading_after_blocker_fails_closed(self):
        # Codex P1: these headings did not match the old detector, so the
        # second entry's fields (Severity: tracked) overwrote the open
        # blocker's and gate_pak returned nothing.
        for heading in ("##### DEF-002", "###### DEF-002", "###DEF-002",
                        "### def-002", "####### DEF-002 (deep)"):
            with self.subTest(heading=heading):
                p = self.write(registry(
                    entry(1, "template"),
                    entry(2, "template", severity="tracked", heading=heading)))
                with self.assertRaises(defect_gate.DefectRegistryError):
                    defect_gate.gate_pak("template", p)
                self.assertEqual(self.run_cli(p, "template"), 1)

    def test_prose_heading_is_not_a_defect(self):
        p = self.write(registry(entry(1, "unifi")) + "\n### DEFECTS ELSEWHERE\n\nprose\n")
        self.assertEqual(defect_gate.gate_pak("template", p), [])

    def test_multi_token_affects_fails_closed(self):
        for affects in ("template (also unifi)", "`template`", "template, unifi",
                        "template,unifi"):
            with self.subTest(affects=affects):
                p = self.write(registry(entry(1, "unifi"), entry(2, affects)))
                with self.assertRaises(defect_gate.DefectRegistryError):
                    defect_gate.gate_pak("template", p)
                self.assertEqual(self.run_cli(p, "template"), 1)

    # --- case-insensitive Affects -----------------------------------------

    def test_affects_case_insensitive(self):
        p = self.write(registry(entry(1, "Template"), entry(2, " TEMPLATE ")))
        hits = defect_gate.gate_pak("template", p)
        self.assertEqual([e.id for e in hits], ["DEF-001", "DEF-002"])
        self.assertEqual(self.run_cli(p, "template"), 2)
        self.assertEqual(len(defect_gate.gate_pak("TEMPLATE", p)), 2)

    def test_gate_item_case_insensitive(self):
        p = self.write(registry(entry(1, "Dashboard/My_Dash")))
        self.assertEqual(len(defect_gate.gate_item("dashboard", "my_dash", p)), 1)

    # --- trailing heading text --------------------------------------------

    def test_heading_with_trailing_text_still_gates(self):
        # Before: the heading did not match, so DEF-002's fields merged into
        # DEF-001 (unifi) and the template defect gated nothing.
        p = self.write(registry(entry(1, "unifi"),
                                entry(2, "template",
                                      heading="### DEF-002 (template build 2)")))
        hits = defect_gate.gate_pak("template", p)
        self.assertEqual([e.id for e in hits], ["DEF-002"])
        self.assertEqual(self.run_cli(p, "template"), 2)

    # --- unchanged behaviour ----------------------------------------------

    def test_clear_and_other_paks(self):
        p = self.write(registry(entry(1, "unifi"), entry(2, "template", severity="tracked")))
        self.assertEqual(defect_gate.gate_pak("template", p), [])
        self.assertEqual(self.run_cli(p, "template"), 0)
        self.assertEqual(self.run_cli(p, "unifi"), 2)


if __name__ == "__main__":
    unittest.main()
