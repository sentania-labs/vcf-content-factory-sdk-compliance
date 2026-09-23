"""Adapter-repo post-normalization deltas shared by the SCG drivers.

Each delta rewrites canonical rows produced by the factory normalizers
(scripts/normalize_scg_v8.py / normalize_scg_v9.py / the 7.0 driver) so a
fix lives in ONE place and regenerates reproducibly. Standard library only.
"""

from __future__ import annotations

import csv
from typing import Dict, List


def reset_port_to_portgroup(rows: List[Dict[str, str]]) -> int:
    """Build 72 (review of build 71, BLOCKING): move `vds.network-reset-port`
    to the distributed portgroup.

    The control's read, `bool:config.policy.portConfigResetAtDisconnect`, is
    a field of the PORTGROUP policy (DVPortgroupPolicy, inherited by
    VMwareDVSPortgroupPolicy). A distributed switch's `config.policy` is a
    DVSPolicy, which has no such field, so on a vDS the read was always
    unreadable: every switch permanently non-compliant with a collection
    alert nobody could clear. SCG 9.1 already carries the control as
    `dvpg.network-reset-port` on DistributedVirtualPortgroup with the same
    read and expected value (the requirement is the same: reset per-port
    configuration when a VM disconnects), so 7.0 / 8.0 / 9.0 now use that
    control_id and kind too, and the per-control alert is shared.

    Returns the number of rows changed; raises if it finds none, so a
    factory change that renames the control fails the run loudly.
    """
    n = 0
    for r in rows:
        if r["control_id"] == "vds.network-reset-port":
            if r.get("read_recipe", "") != (
                    "bool:config.policy.portConfigResetAtDisconnect"):
                raise SystemExit("ERROR: vds.network-reset-port read changed "
                                 f"to {r.get('read_recipe')!r}; review the "
                                 "reset-port delta")
            r["control_id"] = "dvpg.network-reset-port"
            r["resource_kind"] = "DistributedVirtualPortgroup"
            n += 1
    if n == 0:
        raise SystemExit("ERROR: no vds.network-reset-port row found; the "
                         "reset-port delta is stale")
    return n


def rewrite(path: str, base, delta) -> int:
    """Read a canonical CSV, apply `delta` to its rows, write it back
    through the factory's own writer (`base.write_canonical`)."""
    with open(path, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    n = delta(rows)
    base.write_canonical(path, rows)
    return n
