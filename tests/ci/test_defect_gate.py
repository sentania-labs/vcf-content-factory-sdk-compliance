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

    def test_indented_heading_one_to_three_spaces_parses(self):
        # Codex P1 (unifi PR #37): an indented open blocker, with another
        # unindented entry present, was parsed by neither regex and dropped.
        for pad in (" ", "  ", "   "):
            with self.subTest(indent=len(pad)):
                p = self.write(registry(
                    entry(1, "unifi"),
                    entry(2, "template", heading=pad + "### DEF-002")))
                hits = defect_gate.gate_pak("template", p)
                self.assertEqual([e.id for e in hits], ["DEF-002"])
                self.assertEqual(self.run_cli(p, "template"), 2)

    def test_heading_indented_as_code_block_fails_closed(self):
        for pad in ("    ", "      ", "\t", " \t"):
            with self.subTest(indent=repr(pad)):
                p = self.write(registry(
                    entry(1, "unifi"),
                    entry(2, "template", heading=pad + "### DEF-002")))
                with self.assertRaises(defect_gate.DefectRegistryError):
                    defect_gate.gate_pak("template", p)
                self.assertEqual(self.run_cli(p, "template"), 1)

    def indented_fields(self, pad: str) -> str:
        text = entry(2, "template")
        return "\n".join(pad + l if l.startswith("- **") else l
                         for l in text.splitlines()) + "\n"

    def test_fields_indented_one_to_three_spaces_parse(self):
        for pad in (" ", "  ", "   "):
            with self.subTest(indent=len(pad)):
                p = self.write(registry(entry(1, "unifi"), self.indented_fields(pad)))
                hits = defect_gate.gate_pak("template", p)
                self.assertEqual([e.id for e in hits], ["DEF-002"])
                self.assertEqual(hits[0].severity, "blocking")
                self.assertEqual(self.run_cli(p, "template"), 2)

    def test_fields_indented_as_code_block_fail_closed(self):
        for pad in ("    ", "\t", " \t"):
            with self.subTest(indent=repr(pad)):
                p = self.write(registry(entry(1, "unifi"), self.indented_fields(pad)))
                with self.assertRaises(defect_gate.DefectRegistryError):
                    defect_gate.gate_pak("template", p)
                self.assertEqual(self.run_cli(p, "template"), 1)

    def test_one_deep_indented_status_line_fails_closed(self):
        # Only the Status line in a code-block indent: before, it was glued
        # onto the previous field and the entry failed later or not at all.
        text = entry(2, "template").replace("- **Status:**", "    - **Status:**")
        p = self.write(registry(entry(1, "unifi"), text))
        self.assertEqual(self.run_cli(p, "template"), 1)

    # --- peer review on f87a544 -------------------------------------------

    def nested_under_summary(self, line: str) -> str:
        text = entry(2, "template")
        return text.replace("- **Summary:** it broke",
                            "- **Summary:** it broke\n" + line)

    def test_nested_field_shaped_bullet_never_passes(self):
        # A sub-bullet under Summary shaped like a field used to overwrite
        # the real field: "  - **Status:** closed" made an open blocker vanish.
        for line in ("  - **Status:** closed", "  - **Severity:** tracked",
                     "  - **Affects:** unifi", " - **Status:** closed",
                     "   - **Severity:** tracked",
                     "  - **Status:** closed\n  - **Closing-evidence:** fixed in build 3"):
            with self.subTest(line=line):
                p = self.write(registry(entry(1, "unifi"),
                                        self.nested_under_summary(line)))
                # Malformed, exit 1; above all never 0 (the blocker vanishing).
                self.assertEqual(self.run_cli(p, "template"), 1)

    def test_repeated_field_fails_closed(self):
        # Last-wins is how the hole worked: a second Severity: tracked used
        # to turn an open blocker into a pass (exit 0).
        for extra in ("- **Severity:** tracked", "- **Status:** closed",
                      "- **Affects:** unifi"):
            with self.subTest(extra=extra):
                text = entry(2, "template").replace(
                    "- **Summary:** it broke", "- **Summary:** it broke\n" + extra)
                p = self.write(registry(entry(1, "unifi"), text))
                self.assertEqual(self.run_cli(p, "template"), 1)

    def test_indented_example_in_intro_is_skipped(self):
        intro = ("# Defect registry\n\nSchema example:\n\n"
                 "    ### DEF-NNN\n    - **Affects:** <pak>\n\n## Defects\n\n")
        p = self.write(registry(entry(1, "template"), preamble=intro))
        self.assertEqual([e.id for e in defect_gate.gate_pak("template", p)], ["DEF-001"])
        self.assertEqual(self.run_cli(p, "unifi"), 0)

    def test_fenced_example_in_intro_is_skipped(self):
        intro = ("# Defect registry\n\n```\n### DEF-NNN\n- **Affects:** <pak>\n```\n\n"
                 "## Defects\n\n")
        p = self.write(registry(entry(1, "template"), preamble=intro))
        self.assertEqual(self.run_cli(p, "template"), 2)

    def test_fence_content_is_description_not_fields(self):
        text = entry(2, "template").replace(
            "- **Summary:** it broke",
            "- **Summary:** it broke\n```\n- **Status:** closed\n- **Severity:** tracked\n```")
        p = self.write(registry(entry(1, "unifi"), text))
        hits = defect_gate.gate_pak("template", p)
        self.assertEqual([(e.id, e.status, e.severity) for e in hits],
                         [("DEF-002", "open", "blocking")])
        self.assertEqual(self.run_cli(p, "template"), 2)

    def test_def_heading_inside_fence_fails_closed(self):
        text = entry(1, "unifi").replace(
            "- **Summary:** it broke",
            "- **Summary:** it broke\n```\n" + entry(2, "template") + "```")
        p = self.write(registry(text))
        self.assertEqual(self.run_cli(p, "template"), 1)

    def test_bom_does_not_hide_first_heading(self):
        d = Path(tempfile.mkdtemp())
        p = d / "defects.md"
        p.write_bytes(b"\xef\xbb\xbf" + entry(1, "template").encode("utf-8"))
        self.assertEqual([e.id for e in defect_gate.gate_pak("template", p)], ["DEF-001"])
        self.assertEqual(self.run_cli(p, "template"), 2)

    def test_nbsp_or_blockquote_heading_fails_closed(self):
        for heading in ("\u00a0### DEF-002", "> ### DEF-002", ">### DEF-002",
                        "###\u00a0DEF-002"):
            with self.subTest(heading=heading):
                p = self.write(registry(entry(1, "unifi"),
                                        entry(2, "template", heading=heading)))
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
