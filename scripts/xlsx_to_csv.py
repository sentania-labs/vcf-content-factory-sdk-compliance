#!/usr/bin/env python3
"""Convert one worksheet of a vendor SCG controls workbook to CSV.

Usage:
  python3 scripts/xlsx_to_csv.py <workbook.xlsx> <sheet name> \
      <header first-cell> <output.csv>

Used for the SCG releases upstream only ever published as .xlsx
(vSphere 6.7 and 7.0; see CANONICAL_SCHEMA.md "Source provenance").
The output is the verbatim source for the normalizer: the header row
and every data row below it, cell text unchanged, no column dropped
except trailing columns with no header and no data. Rows above the
header (workbook title / version banner) and fully blank rows are
not carried.

Cell rendering matches what Excel's own "Save as CSV" produces, which
is what the existing vmware_scg_8.0.csv source looks like:

- boolean cells -> TRUE / FALSE
- numeric cells -> integral values without a trailing ".0"
- string / rich-text cells -> text as stored (embedded newlines kept)

Standard library only (zipfile + ElementTree), so any clone of the
factory can re-run the conversion without an extra dependency.
Cached formula results are used; neither shipped workbook carries
formulas in the controls sheets.

To reproduce the shipped sources from the upstream clone
(reference/references/vcf-security-and-compliance-guidelines):

  git show '8300517^:security-configuration-hardening-guide/vsphere/7.0/VMware vSphere Security Configuration Guide 7 - Controls.xlsx' > scg7.xlsx
  python3 scripts/xlsx_to_csv.py scg7.xlsx Controls 'SCG ID' profiles/vmware_scg_7.0.csv

  git show '8300517^:security-configuration-hardening-guide/vsphere/6.7/VMware vSphere Security Configuration Guide 6.7 - Controls - 671-20210210-01.xlsx' > scg67.xlsx
  python3 scripts/xlsx_to_csv.py scg67.xlsx 'vSphere 6.7' 'Guideline ID' profiles/vmware_scg_6.7.csv
"""

from __future__ import annotations

import csv
import re
import sys
import zipfile
import xml.etree.ElementTree as ET

NS = {
    "m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
}
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"


def _text(node) -> str:
    """Concatenate every <t> under a shared-string / inline-string node
    (rich text is split across several runs)."""
    return "".join(t.text or "" for t in node.iter(f"{{{NS['m']}}}t"))


def _col_index(ref: str) -> int:
    letters = re.match(r"[A-Z]+", ref).group(0)
    n = 0
    for ch in letters:
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def _render_number(raw: str) -> str:
    try:
        f = float(raw)
    except ValueError:
        return raw
    if f.is_integer():
        return str(int(f))
    return raw


def read_sheet(path: str, sheet_name: str) -> list:
    with zipfile.ZipFile(path) as z:
        shared = []
        if "xl/sharedStrings.xml" in z.namelist():
            root = ET.fromstring(z.read("xl/sharedStrings.xml"))
            shared = [_text(si) for si in root.findall("m:si", NS)]

        wb = ET.fromstring(z.read("xl/workbook.xml"))
        rid = None
        for s in wb.find("m:sheets", NS):
            if s.get("name") == sheet_name:
                rid = s.get(f"{{{NS['r']}}}id")
        if rid is None:
            raise SystemExit(f"ERROR: sheet {sheet_name!r} not in {path}")
        rels = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
        target = None
        for rel in rels.findall(f"{{{REL_NS}}}Relationship"):
            if rel.get("Id") == rid:
                target = rel.get("Target")
        target = target.lstrip("/")
        if not target.startswith("xl/"):
            target = "xl/" + target
        sheet = ET.fromstring(z.read(target))

    rows = []
    for row in sheet.iter(f"{{{NS['m']}}}row"):
        cells = {}
        for c in row.findall("m:c", NS):
            t = c.get("t")
            v = c.find("m:v", NS)
            if t == "s":
                val = shared[int(v.text)] if v is not None else ""
            elif t == "inlineStr":
                is_ = c.find("m:is", NS)
                val = _text(is_) if is_ is not None else ""
            elif t == "b":
                val = "TRUE" if (v is not None and v.text == "1") else "FALSE"
            elif t in ("str", "e"):
                val = v.text if v is not None and v.text else ""
            else:
                val = _render_number(v.text) if v is not None and v.text else ""
            cells[_col_index(c.get("r"))] = val
        width = max(cells) + 1 if cells else 0
        rows.append([cells.get(i, "") for i in range(width)])
    return rows


def convert(path: str, sheet_name: str, header_first: str, out: str) -> int:
    rows = read_sheet(path, sheet_name)
    hdr_idx = None
    for i, r in enumerate(rows):
        if r and r[0].strip() == header_first:
            hdr_idx = i
            break
    if hdr_idx is None:
        raise SystemExit(
            f"ERROR: no row starting {header_first!r} in sheet {sheet_name!r}")
    header = rows[hdr_idx]
    data = [r for r in rows[hdr_idx + 1:] if any(x.strip() for x in r)]
    # Keep every column that has a header or carries data; drop only
    # trailing columns with neither.
    width = 0
    for i in range(max([len(header)] + [len(r) for r in data])):
        has_hdr = i < len(header) and header[i].strip()
        has_data = any(i < len(r) and r[i].strip() for r in data)
        if has_hdr or has_data:
            width = i + 1
    with open(out, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        for r in [header] + data:
            w.writerow((r + [""] * width)[:width])
    print(f"[xlsx_to_csv] {sheet_name}: {len(data)} data rows, "
          f"{width} columns -> {out}", file=sys.stderr)
    return 0


def main(argv: list) -> int:
    if len(argv) != 5:
        print("usage: xlsx_to_csv.py <workbook.xlsx> <sheet> "
              "<header first-cell> <output.csv>", file=sys.stderr)
        return 2
    return convert(argv[1], argv[2], argv[3], argv[4])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
