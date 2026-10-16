"""Registry reader for ``context/defects.md``.

Parses the defect registry into :class:`DefectEntry` dataclasses and exposes
the gate logic used by ``defect-gate``, ``release``, and ``publish``.

Public API
----------
load_registry(registry_path) -> List[DefectEntry]
    Parse the registry file.  Raises :class:`DefectRegistryError` on any
    malformed entry.  Hard errors on:
      - unknown ``Severity:`` (only ``blocking`` or ``tracked`` are valid)
      - ``waived`` status (explicitly rejected — no waivers exist)
      - unknown ``Status:`` (only ``open`` or ``closed`` are valid)
      - ``status: closed`` without a non-empty ``Closing-evidence:`` field
      - duplicate IDs
      - missing required fields (Title, Severity, Status, Affects, First-seen,
        Source, Summary)
      - a ``DEF-`` heading whose id is not ``DEF-NNN`` (a typo such as
        ``DEF-1O2``), which would otherwise merge its fields into the
        previous entry
      - zero parsed entries (an empty, truncated or reformatted registry is
        unrecognised, never an all-clear)
      - an ``Affects:`` value that is not one token (whitespace, a comma or a
        backtick), which would otherwise match no pak and gate nothing
      - a DEF heading or field line indented like a code block (a tab or 4+
        spaces), inside a blockquote, behind a non-breaking space, or (a
        heading) inside a fenced code block, after the first entry
      - a field-shaped line at a different indent from the entry's first
        field (a nested sub-bullet), or a field repeated within one entry
    Fenced code blocks are description text; indented or fenced examples
    before the first entry are skipped. The file is read as utf-8-sig.

gate_pak(pak_name, registry_path) -> List[DefectEntry]
    Return all open blocking defects whose ``Affects:`` token is ``pak_name``
    (compared case-insensitively).
    Raises :class:`DefectRegistryError` if the registry is malformed.

gate_item(content_type, slug, registry_path) -> List[DefectEntry]
    Return all open blocking defects whose ``Affects:`` token is
    ``<content_type>/<slug>``.

gate_all(registry_path) -> List[DefectEntry]
    Return all open blocking defects in the registry.

format_defect_line(entry) -> str
    Format one defect for human output:
    ``DEF-NNN  <title>  (first seen <first_seen>, source <source>)``

REGISTRY_PATH
    Default registry path (``context/defects.md`` relative to repo root).

Registry file format
--------------------
Each entry is a ``### DEF-NNN`` section.  Field lines are:

    - **Field:** value

Required fields: Title, Severity, Status, Affects, First-seen, Source, Summary.
Optional fields: Closing-evidence (required when Status is ``closed``), Related.

``Affects:`` is exactly one token — a managed-pak name (e.g. ``synology``), a
``<type>/<slug>`` path (e.g. ``dashboard/demand_driven_capacity_v2``), or a
``factory:<area>`` string for framework-level defects.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

#: Default path to the defect registry, relative to the repo root.
REGISTRY_PATH = Path(__file__).parent.parent / "context" / "defects.md"

#: Valid severity values.
_VALID_SEVERITIES = frozenset({"blocking", "tracked"})

#: Valid status values.
_VALID_STATUSES = frozenset({"open", "closed"})


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------

@dataclass
class DefectEntry:
    """One entry in the defect registry."""

    id: str                      # e.g. "DEF-001"
    title: str                   # one line; quoted in refusal messages
    severity: str                # "blocking" or "tracked"
    status: str                  # "open" or "closed"
    affects: str                 # single token: pak name, <type>/<slug>, or factory:<area>
    first_seen: str              # build + date string as written in the registry
    source: str                  # path (+ finding label) of the review that found it
    summary: str                 # 2-4 line description
    closing_evidence: str = ""   # non-empty iff status == "closed"
    related: str = ""            # optional cross-links


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class DefectRegistryError(ValueError):
    """Raised when the defect registry is malformed.

    ``python3 -m vcfops_packaging defect-gate`` exits 1 on this error;
    ``release`` and ``publish`` also exit non-zero so the malformed registry
    is never silently treated as an all-clear.
    """


# ---------------------------------------------------------------------------
# Regex patterns  (mirror managed_paks.py style: per-field regexes)
# ---------------------------------------------------------------------------

# A section heading: the id, then optional trailing text after a word break
# ("### DEF-027 (synology build 32)"). Before template ci/ build 2 the
# heading had to end at the id, and a heading with trailing text was not
# seen as a section at all, so its fields merged into the previous entry
# and the defect gated nothing (issue #18 CI4).
_SECTION_RE = re.compile(r"^#{1,4}[ \t]+(DEF-\d+)\b.*$")
# Any heading, at ANY depth, that starts like a defect id: any run of '#',
# optional spaces, then DEF- in any case. One that does not also match
# _SECTION_RE ("### DEF-1O2", "##### DEF-002", "###DEF-003", "### def-004")
# is malformed: fail closed. Otherwise its field lines would fall into the
# continuation parser and overwrite the previous entry's fields (Codex P1 on
# PR #22: an open blocker followed by "##### DEF-002" with a tracked
# severity made the blocker vanish).
_DEF_HEADING_RE = re.compile(r"^#+\s*DEF-", re.IGNORECASE)
# Leading whitespace before a heading. Markdown allows up to three spaces
# before an ATX heading; four or more spaces (or a tab) make the line an
# indented code block, not a heading. Both regexes above, and _FIELD_RE, are
# matched after this indent is split off (Codex P1 on unifi PR #37: an indented open
# blocker was parsed by neither and silently dropped).
_INDENT_RE = re.compile(r"^([ \t]*)(.*)$")
# Loose shapes, used to catch a heading or field that is disguised: any
# leading run of whitespace (including a non-breaking space) and blockquote
# markers. A line that matches a loose shape but not the strict one is
# malformed and fails closed, so nothing that LOOKS like a defect heading or
# field can be skipped or mis-parsed.
_LOOSE_DEF_HEADING_RE = re.compile(r"^[\s>]*#+\s*DEF-", re.IGNORECASE)
_LOOSE_FIELD_RE = re.compile(r"^[\s>]*-\s+\*\*[^:]+:\*\*")
# A fenced code block delimiter (indent already split off): ``` or ~~~,
# three or more, optional info string on the opening fence.
_FENCE_RE = re.compile(r"^(`{3,}|~{3,})(.*)$")
# The id tail (after "DEF-") of a heading that may sit inside a fence before
# the first entry: a placeholder with no digit, such as the "NNN" in the
# schema example "### DEF-NNN". Any digit in the id fails closed.
_FENCED_PLACEHOLDER_ID_RE = re.compile(r"^[^\d\s]+(?:\s|$)")
_FIELD_RE = re.compile(r"^-\s+\*\*([^:]+):\*\*\s*(.*)")

# Anything that makes an Affects value more than one bare token.
_MULTI_TOKEN_RE = re.compile(r"[\s,`]")

# DEF-NNN id format.
_ID_RE = re.compile(r"^DEF-\d+$")

#: Required field names (exact, case-sensitive as they appear in the registry).
_REQUIRED_FIELDS = ("Title", "Severity", "Status", "Affects", "First-seen", "Source", "Summary")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def load_registry(
    registry_path: "str | Path | None" = None,
) -> List[DefectEntry]:
    """Parse ``context/defects.md`` and return all entries.

    The registry is parsed strictly:
    - Unknown ``Severity:`` values raise :class:`DefectRegistryError`.
    - ``waived`` status raises :class:`DefectRegistryError` explicitly.
    - Unknown ``Status:`` values raise :class:`DefectRegistryError`.
    - ``Status: closed`` without a non-empty ``Closing-evidence:`` raises
      :class:`DefectRegistryError` — an unevidenced close is treated as
      malformed, never as closed.
    - Duplicate IDs raise :class:`DefectRegistryError`.
    - Missing required fields raise :class:`DefectRegistryError`.

    Multi-line field values (``Summary:``, ``Closing-evidence:``,
    ``Related:``) are assembled by appending continuation lines (any line that
    does not start ``- **`` or ``###`` and is not blank between two field
    lines) to the last field seen in the current entry.

    Args:
        registry_path: Path to the registry file.  Defaults to
            ``context/defects.md`` relative to the repo root.

    Returns:
        A list of :class:`DefectEntry` objects in document order.

    Raises:
        FileNotFoundError: if the registry file does not exist.
        DefectRegistryError: if any entry is malformed.
    """
    if registry_path is None:
        registry_path = REGISTRY_PATH
    registry_path = Path(registry_path)
    if not registry_path.exists():
        raise FileNotFoundError(f"defect registry not found: {registry_path}")

    # utf-8-sig: a byte-order mark must not hide a first-line heading.
    lines = registry_path.read_text(encoding="utf-8-sig").splitlines()

    entries: List[DefectEntry] = []
    seen_ids: dict[str, int] = {}  # id -> line number for dup detection

    # Parser state for the current entry.
    current_id: Optional[str] = None
    current_fields: dict[str, str] = {}
    current_last_field: Optional[str] = None
    current_id_lineno: int = 0
    field_indent: Optional[int] = None   # indent of the entry's first field
    fence: Optional[str] = None          # opening fence while inside one

    def _flush_entry(lineno: int) -> None:
        """Validate and emit the current entry."""
        nonlocal current_id, current_fields, current_last_field
        if current_id is None:
            return
        _validate_and_emit(current_id, current_fields, current_id_lineno, entries, seen_ids)
        current_id = None
        current_fields = {}
        current_last_field = None

    def _append(text: str) -> None:
        """Description text: continue the last field's value, if any."""
        if current_last_field is not None and text.strip():
            current_fields[current_last_field] = (
                current_fields[current_last_field] + " " + text.strip()
            )

    for lineno, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip()
        # Up to three spaces of indent are allowed before a heading, a field
        # or a fence; four or more, or a tab, make the line an indented code
        # block in Markdown.
        indent, rest = _INDENT_RE.match(line).groups()
        code_indent = "\t" in indent or len(indent) > 3

        # --- Fenced code blocks ---
        # Lines inside a fence are description text, never fields or
        # headings. A defect heading inside a fence fails closed: a defect
        # must not hide in a code block. Before the first entry the only
        # exception is a schema placeholder with no digit in its id (the
        # literal "### DEF-NNN"); a numeric id there fails closed too (Codex
        # P1: a fence opened before "### DEF-001" hid that open blocker while
        # a later DEF-002 made the registry look valid).
        m_fence = None if code_indent else _FENCE_RE.match(rest)
        if fence is not None:
            if (m_fence and m_fence.group(1)[0] == fence[0]
                    and len(m_fence.group(1)) >= len(fence)
                    and not m_fence.group(2).strip()):
                fence = None
                continue
            m_fenced_def = _LOOSE_DEF_HEADING_RE.match(line)
            if m_fenced_def and (
                    current_id is not None
                    or _FENCED_PLACEHOLDER_ID_RE.match(line[m_fenced_def.end():])
                    is None):
                raise DefectRegistryError(
                    f"line {lineno}: defect heading {line.strip()!r} is inside "
                    f"a fenced code block; refusing to guess"
                )
            if current_id is not None:
                _append(line)
            continue
        if m_fence:
            fence = m_fence.group(1)
            continue

        # --- Before the first entry ---
        # The registry's introduction may show schema examples as indented
        # code; those are skipped. Everything else that looks like a defect
        # heading is checked strictly, here and after.
        if current_id is None and code_indent:
            continue

        # --- New entry section heading ---
        if _LOOSE_DEF_HEADING_RE.match(line):
            if code_indent:
                raise DefectRegistryError(
                    f"line {lineno}: defect heading {rest!r} is indented like "
                    f"a code block (a tab or 4+ spaces); refusing to guess"
                )
            m_section = _SECTION_RE.match(rest)
            if not m_section:
                raise DefectRegistryError(
                    f"line {lineno}: {line.strip()!r} starts like a defect "
                    f"heading but is not '### DEF-NNN' (a bad id, too deep, a "
                    f"blockquote, or a non-breaking space); refusing to guess"
                )
            _flush_entry(lineno)
            current_id = m_section.group(1)
            current_id_lineno = lineno
            current_fields = {}
            current_last_field = None
            field_indent = None
            continue

        # Skip lines before the first entry.
        if current_id is None:
            continue

        # --- Field line ---
        # Fail closed on anything field-shaped that is not a plain field at
        # this entry's field indent: a code-block indent, a blockquote or a
        # non-breaking space, a different indent (a nested sub-bullet such
        # as "  - **Status:** closed" under Summary), or a repeated field.
        # Each of those used to be able to overwrite or drop a real field.
        if _LOOSE_FIELD_RE.match(line):
            if code_indent:
                raise DefectRegistryError(
                    f"line {lineno}: field line {rest!r} in {current_id} is "
                    f"indented like a code block (a tab or 4+ spaces); "
                    f"refusing to guess"
                )
            m_field = _FIELD_RE.match(rest)
            if not m_field:
                raise DefectRegistryError(
                    f"line {lineno}: {line.strip()!r} in {current_id} looks "
                    f"like a field but is prefixed by a blockquote or a "
                    f"non-breaking space; refusing to guess"
                )
            if field_indent is None:
                field_indent = len(indent)
            elif len(indent) != field_indent:
                raise DefectRegistryError(
                    f"line {lineno}: field line {rest!r} in {current_id} is "
                    f"indented {len(indent)} space(s) but the entry's fields "
                    f"are at {field_indent} (a nested bullet shaped like a "
                    f"field?); refusing to guess"
                )
            fname = m_field.group(1).strip()
            if fname in current_fields:
                raise DefectRegistryError(
                    f"line {lineno}: field {fname!r} appears twice in "
                    f"{current_id}; refusing to pick one"
                )
            current_fields[fname] = m_field.group(2).strip()
            current_last_field = fname
            continue

        # --- Continuation line (part of a multi-line field value) ---
        # A non-blank, non-section, non-field line that follows a field line
        # is appended to the last field's value (handles Summary, Closing-
        # evidence, etc. which can span 2-4 lines in the markdown).
        if line.strip():
            _append(line)
            continue

        # Blank line: clear the continuation pointer so a blank line between
        # fields doesn't accidentally merge separate fields.
        current_last_field = None

    # Flush the last entry.
    _flush_entry(len(lines) + 1)

    # Fail closed: a registry with no parsable entry is unrecognised (empty,
    # truncated, an error page, or a format change), never an all-clear.
    if not entries:
        raise DefectRegistryError(
            f"{registry_path}: no '### DEF-NNN' entries parsed; the registry "
            f"is empty or in an unrecognised format. Refusing to treat it as "
            f"clear."
        )

    return entries


def _validate_and_emit(
    entry_id: str,
    fields: dict[str, str],
    lineno: int,
    entries: List[DefectEntry],
    seen_ids: dict[str, int],
) -> None:
    """Validate one entry's field dict and append it to ``entries``.

    Raises :class:`DefectRegistryError` on any violation.
    """
    loc = f"{entry_id} (near line {lineno})"

    # --- Duplicate ID check ---
    if entry_id in seen_ids:
        raise DefectRegistryError(
            f"duplicate defect id {entry_id!r}: first seen near line "
            f"{seen_ids[entry_id]}, duplicate near line {lineno}"
        )
    seen_ids[entry_id] = lineno

    # --- Required fields ---
    for req in _REQUIRED_FIELDS:
        if req not in fields or not fields[req].strip():
            raise DefectRegistryError(
                f"{loc}: required field {req!r} is missing or empty"
            )

    title = fields["Title"].strip()
    severity = fields["Severity"].strip().lower()
    status = fields["Status"].strip().lower()
    affects = fields["Affects"].strip()
    first_seen = fields["First-seen"].strip()
    source = fields["Source"].strip()
    summary = fields["Summary"].strip()
    closing_evidence = fields.get("Closing-evidence", "").strip()
    related = fields.get("Related", "").strip()

    # --- Affects must be exactly one scope token ---
    # "template (also unifi)", "`template`" or "synology, unifi" matches no
    # pak, so the entry would silently gate nothing. The registry schema
    # calls such an entry malformed; fail closed (issue #18 CI4 follow-up).
    if _MULTI_TOKEN_RE.search(affects):
        raise DefectRegistryError(
            f"{loc}: Affects {affects!r} is not one scope token (it contains "
            f"whitespace, a comma or a backtick). Use exactly one pak name, "
            f"<type>/<slug> or factory:<area>; one issue on N artifacts is N "
            f"entries."
        )

    # --- Severity validation ---
    if severity not in _VALID_SEVERITIES:
        raise DefectRegistryError(
            f"{loc}: invalid Severity {severity!r}. "
            f"Allowed: {', '.join(sorted(_VALID_SEVERITIES))}"
        )

    # --- Status validation (waived is explicitly rejected) ---
    if status == "waived":
        raise DefectRegistryError(
            f"{loc}: 'waived' is not a valid Status. "
            f"To ship a defect, downgrade Severity to 'tracked' with a dated note — "
            f"the git diff is the audit trail. See rules/release-gate-defects.md."
        )
    if status not in _VALID_STATUSES:
        raise DefectRegistryError(
            f"{loc}: invalid Status {status!r}. "
            f"Allowed: {', '.join(sorted(_VALID_STATUSES))}. "
            f"Note: 'waived' is not accepted — see rules/release-gate-defects.md."
        )

    # --- Closed-without-evidence check ---
    if status == "closed" and not closing_evidence:
        raise DefectRegistryError(
            f"{loc}: Status is 'closed' but Closing-evidence is absent or empty. "
            f"A close without evidence is invalid — provide concrete proof "
            f"(fix commit/build, devel proof, lesson). "
            f"See context/defects.md schema and rules/release-gate-defects.md."
        )

    entries.append(DefectEntry(
        id=entry_id,
        title=title,
        severity=severity,
        status=status,
        affects=affects,
        first_seen=first_seen,
        source=source,
        summary=summary,
        closing_evidence=closing_evidence,
        related=related,
    ))


# ---------------------------------------------------------------------------
# Gate helpers
# ---------------------------------------------------------------------------

def gate_pak(
    pak_name: str,
    registry_path: "str | Path | None" = None,
) -> List[DefectEntry]:
    """Return all open blocking defects that affect ``pak_name``.

    ``pak_name`` is matched against the ``Affects:`` token, ignoring case
    and surrounding spaces, so ``Synology`` in the registry still gates the
    ``synology`` pak (issue #18 CI4).

    Args:
        pak_name:      Managed pak name to check.
        registry_path: Path to the registry; defaults to ``context/defects.md``.

    Returns:
        List of open blocking :class:`DefectEntry` objects.  Empty list = clean.

    Raises:
        FileNotFoundError: if the registry file is missing.
        DefectRegistryError: if the registry is malformed.
    """
    entries = load_registry(registry_path)
    want = _norm(pak_name)
    return [
        e for e in entries
        if e.severity == "blocking"
        and e.status == "open"
        and _norm(e.affects) == want
    ]


def gate_item(
    content_type: str,
    slug: str,
    registry_path: "str | Path | None" = None,
) -> List[DefectEntry]:
    """Return all open blocking defects that affect ``<content_type>/<slug>``.

    The ``Affects:`` token is matched, ignoring case, as ``<content_type>/<slug>``.
    ``content_type`` is the singular directory name (e.g. ``"dashboard"``,
    ``"view"``).  ``slug`` is the filename stem (e.g.
    ``"demand_driven_capacity_v2"``).

    Note on slug vs. name: callers should pass the filename stem (slug) of
    the source YAML, not the display name.  The defect registry's ``Affects:``
    field uses the ``<type>/<slug>`` form, not the display name.

    Args:
        content_type:  Singular content type name.
        slug:          Filename stem of the content item.
        registry_path: Path to the registry; defaults to ``context/defects.md``.

    Returns:
        List of open blocking :class:`DefectEntry` objects.  Empty list = clean.

    Raises:
        FileNotFoundError: if the registry file is missing.
        DefectRegistryError: if the registry is malformed.
    """
    token = _norm(f"{content_type}/{slug}")
    entries = load_registry(registry_path)
    return [
        e for e in entries
        if e.severity == "blocking"
        and e.status == "open"
        and _norm(e.affects) == token
    ]


def gate_all(
    registry_path: "str | Path | None" = None,
) -> List[DefectEntry]:
    """Return all open blocking defects in the registry.

    Args:
        registry_path: Path to the registry; defaults to ``context/defects.md``.

    Returns:
        List of open blocking :class:`DefectEntry` objects.  Empty list = clean.

    Raises:
        FileNotFoundError: if the registry file is missing.
        DefectRegistryError: if the registry is malformed.
    """
    entries = load_registry(registry_path)
    return [
        e for e in entries
        if e.severity == "blocking"
        and e.status == "open"
    ]


def _norm(token: str) -> str:
    """An ``Affects:`` token for comparison: trimmed, lower-case."""
    return (token or "").strip().lower()


def format_defect_line(entry: DefectEntry) -> str:
    """Return the human-readable single-line summary for a blocking defect.

    Format::

        DEF-NNN  <title>  (first seen <first_seen>, source <source>)
    """
    return (
        f"{entry.id}  {entry.title}  "
        f"(first seen {entry.first_seen}, source {entry.source})"
    )


# ---------------------------------------------------------------------------
# Standalone entrypoint
#
# This block makes defects.py runnable as a bare script with no package
# install — intended for pak-repo CI that curl's this file alongside
# context/defects.md and invokes:
#
#   python3 defects.py --pak <name> [--registry <path>]
#   python3 defects.py --all        [--registry <path>]
#
# The block must NOT use package-relative imports.  All logic it needs
# (gate_pak, gate_all, format_defect_line, DefectRegistryError) is
# defined above in this same file and is therefore available both when
# the file is run as a script and when it is imported as a module.
#
# Exit codes (match cmd_defect_gate in cli.py):
#   0 — no open blocking defects affect the named pak / no open blockers at all
#   1 — malformed or missing registry (hard error)
#   2 — one or more open blocking defects found
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse as _argparse
    import sys as _sys

    # Default registry: sibling of THIS file, so `curl defects.py` + `curl
    # defects.md` into the same directory and run without --registry works.
    _DEFAULT_REGISTRY = Path(__file__).parent / "defects.md"

    _p = _argparse.ArgumentParser(
        prog="defects.py",
        description=(
            "Defect gate for pak-repo CI. "
            "Reads a defect registry and exits 0 (clean), 1 (bad registry), "
            "or 2 (open blocking defects found)."
        ),
    )
    _mode = _p.add_mutually_exclusive_group(required=True)
    _mode.add_argument(
        "--pak",
        metavar="NAME",
        default=None,
        help="check a managed pak by name (e.g. synology, unifi, compliance)",
    )
    _mode.add_argument(
        "--all",
        action="store_true",
        default=False,
        help="list every open blocking defect across all artifacts",
    )
    _p.add_argument(
        "--registry",
        metavar="PATH",
        default=str(_DEFAULT_REGISTRY),
        help=(
            "path to defects.md registry "
            f"(default: {_DEFAULT_REGISTRY})"
        ),
    )

    _args = _p.parse_args()
    _registry_path = Path(_args.registry)

    try:
        if _args.all:
            _blockers = gate_all(_registry_path)
            if not _blockers:
                print("no open blocking defects")
                _sys.exit(0)
            for _entry in _blockers:
                print(format_defect_line(_entry))
            print(
                f"\n{len(_blockers)} open blocking defect(s) found. "
                f"See RULE-012 and context/defects.md."
            )
            _sys.exit(2)
        else:
            _pak_name = _args.pak
            _blockers = gate_pak(_pak_name, _registry_path)
            if not _blockers:
                print(f"no open blocking defects affecting {_pak_name}")
                _sys.exit(0)
            for _entry in _blockers:
                print(format_defect_line(_entry))
            print(
                f"\n{len(_blockers)} open blocking defect(s) block release of {_pak_name!r}. "
                f"Refused by RULE-012. See context/defects.md."
            )
            _sys.exit(2)

    except FileNotFoundError as _exc:
        print(f"ERROR: registry not found: {_registry_path}", file=_sys.stderr)
        print(f"  ({_exc})", file=_sys.stderr)
        _sys.exit(1)
    except DefectRegistryError as _exc:
        print(
            f"ERROR: defect registry malformed: {_registry_path}",
            file=_sys.stderr,
        )
        print(f"  {_exc}", file=_sys.stderr)
        _sys.exit(1)
