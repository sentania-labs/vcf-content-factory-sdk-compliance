#!/usr/bin/env python3
"""Normalize the VMware SCG 9.0 source CSV to the canonical schema.

Usage (run from the factory checkout the adapter repo is cloned into):
  python3 scripts/normalize_scg_v90.py \\
      profiles/vmware_scg_9.0.csv profiles/canonical/scg_9.0.csv

A thin driver over the factory's SCG 9 normalizer
(`<factory>/scripts/normalize_scg_v9.py`), added in adapter build 72 so
adapter-side corrections to the 9.0 profile regenerate reproducibly.
Deltas (scripts/_adapter_deltas.py):

1. `vds.network-reset-port` moves to DistributedVirtualPortgroup as
   `dvpg.network-reset-port` (its read is a portgroup-policy field; see
   `reset_port_to_portgroup`).
2. Build 74: host encryption rows read
   `esxcli:system.settings.encryption.get`, and the VAMI recipes are
   fixed (`build74` in scripts/_adapter_deltas.py).

The factory normalizer's own output is otherwise unchanged.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _factory_scripts_dir() -> Path:
    here = Path(__file__).resolve()
    candidate = here.parents[4] / "scripts"
    if (candidate / "normalize_scg_v9.py").exists():
        return candidate
    raise SystemExit(
        "ERROR: cannot locate the factory's scripts/normalize_scg_v9.py "
        f"(looked in {candidate}). Run from an adapter clone inside a "
        "vcf-content-factory checkout.")


def main(argv: list) -> int:
    if len(argv) != 3:
        print("usage: normalize_scg_v90.py <input.csv> <output.csv>",
              file=sys.stderr)
        return 2
    sys.path.insert(0, str(_factory_scripts_dir()))
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _compliance_normalize as base
    import normalize_scg_v9 as v9
    import _adapter_deltas as deltas
    rc = v9.normalize(argv[1], argv[2])
    if rc != 0:
        return rc
    n = deltas.rewrite(argv[2], base, deltas.reset_port_to_portgroup)
    got = {}
    deltas.rewrite(argv[2], base, lambda rows: got.update(
        deltas.build74(rows)) or 0)
    if got != {"encryption": 3, "vami": 3}:
        raise SystemExit(f"ERROR: unexpected build-74 delta counts {got}")
    print(f"[normalize_scg_v90] reset-port rows moved to portgroup: {n}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
