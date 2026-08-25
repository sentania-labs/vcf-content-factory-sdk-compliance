#!/usr/bin/env python3
"""Normalize the VMware SCG 9.1 source CSV to the canonical schema.

Usage (run from the factory checkout the adapter repo is cloned into):
  python3 scripts/normalize_scg_v91.py \
      profiles/vmware_scg_9.1.csv profiles/canonical/scg_9.1.csv

This is a thin delta driver over the factory's SCG 9.x normalizer
(`<factory>/scripts/normalize_scg_v9.py` + `_compliance_normalize.py`).
The 9.x pipeline (component mapping, source-ID prefix handling,
Setting Location refinement, every build-35..41 read-recipe reclass
map) is reused verbatim; only the 9.1-specific deltas are applied
here:

1. **Header shapes.** The 9.1 source CSV drops the embedded newlines
   9.0 carried in three header cells:
     9.0: "Secure Controls\nFramework ID" / "Component\nName" /
          "Implementation\nPriority"
     9.1: "Secure Controls Framework ID" / "Component Name" /
          "Implementation Priority"
   9.1 also inserts a new "NIST 800-53R5 ID" column at position 5;
   lookup is by header name, so the insertion is invisible.
2. **Source token.** `source_ref` rows are tagged `SCG-9.1:` instead
   of `SCG-9.0:`.
3. **New sub-products.** 9.1 introduces Component values "Automation"
   (source IDs `automation-9.*`), "Protection and Recovery"
   (`pnr-9.*`), and "Operations for Networks" (`networks-9.*` — the
   source-ID prefix already existed in 9.0 under Component
   "Operations"). Mapped like the other unreachable sub-products:
   informational-only rows (manual_audit / powercli_only), stitched
   nowhere, resource_kind falls back to VCenterAdapterInstance for
   loadability, with their own control_id prefixes (`automation`,
   `pnr`, `networks`) per the CANONICAL_SCHEMA.md prefix table.

The deltas are applied by patching the imported factory modules
in-process (module-level constants and the shared COMPONENT_MAP /
SOURCE_ID_PREFIX_MAP dicts) rather than forking the 300-line driver.
If the factory normalizer grows native 9.1 support, this file
collapses to a two-line invocation.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _factory_scripts_dir() -> Path:
    """The adapter repo is always cloned into a factory checkout at
    content/sdk-adapters/compliance/ (see bootstrap_managed_paks.sh);
    the shared normalizer modules live in the factory's scripts/."""
    here = Path(__file__).resolve()
    candidate = here.parents[4] / "scripts"
    if (candidate / "normalize_scg_v9.py").exists():
        return candidate
    raise SystemExit(
        "ERROR: cannot locate the factory's scripts/normalize_scg_v9.py "
        f"(looked in {candidate}). Run from an adapter clone inside a "
        "vcf-content-factory checkout."
    )


def main(argv: list) -> int:
    if len(argv) != 3:
        print("usage: normalize_scg_v91.py <input.csv> <output.csv>",
              file=sys.stderr)
        return 2

    sys.path.insert(0, str(_factory_scripts_dir()))
    import _compliance_normalize as base
    import normalize_scg_v9 as v9

    # Delta 1: 9.1 header shapes (no embedded newlines).
    v9.COL_COMPONENT = "Component Name"
    v9.COL_PRIORITY = "Implementation Priority"
    # REQUIRED_COLUMNS was built at import time from the 9.0 constants;
    # rebuild it with the 9.1 shapes.
    v9.REQUIRED_COLUMNS = [
        v9.COL_SCG_ID,
        v9.COL_COMPONENT,
        v9.COL_PRIORITY,
        v9.COL_TITLE,
        v9.COL_DESCRIPTION,
        v9.COL_PARAMETER,
        v9.COL_EXPECTED,
        v9.COL_ASSESSMENT,
        v9.COL_REMEDIATION,
    ]

    # Delta 2: source token.
    v9.SOURCE_TOKEN = "SCG-9.1"

    # Delta 3: new 9.1 sub-products (informational-only; see module
    # docstring). resource_kind VCenterAdapterInstance is the same
    # loadability fallback the existing NSX/Operations/SDDC rows use.
    base.COMPONENT_MAP.update({
        "Automation": ("VCenterAdapterInstance", "automation"),
        "Protection and Recovery": ("VCenterAdapterInstance", "pnr"),
        "Operations for Networks": ("VCenterAdapterInstance", "networks"),
    })
    base.SOURCE_ID_PREFIX_MAP.update({
        "automation": ("automation", "VCenterAdapterInstance"),
        "pnr": ("pnr", "VCenterAdapterInstance"),
    })

    return v9.normalize(argv[1], argv[2])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
