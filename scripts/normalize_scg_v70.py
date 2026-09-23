#!/usr/bin/env python3
"""Normalize the VMware vSphere SCG 7 source CSV to the canonical schema.

Usage (run from the factory checkout the adapter repo is cloned into):
  python3 scripts/normalize_scg_v70.py \
      profiles/vmware_scg_7.0.csv profiles/canonical/scg_7.0.csv

Source: profiles/vmware_scg_7.0.csv, converted verbatim from the
"Controls" sheet of "VMware vSphere Security Configuration Guide 7 -
Controls.xlsx" (Version 703-20250422-01) by scripts/xlsx_to_csv.py.
Provenance is recorded in CANONICAL_SCHEMA.md.

SCG 7 is the direct predecessor of the SCG 8 format: same source-ID
shape (`esxi-7.*`, `vcenter-7.*`, `vm-7.*`, `guest-7.*`), same
Setting Location vocabulary, same PowerCLI assessment style. So this
is a thin delta driver over the factory's SCG 8 normalizer
(`<factory>/scripts/normalize_scg_v8.py` + `_compliance_normalize.py`)
and inherits every classifier and control_id-keyed read-recipe map
from it. That inheritance is the point: a 7.0 control whose slug is
unchanged in 8.0 gets the same control_id, and therefore the same
parameter_kind / read_recipe, as its 8.0 row.

Deltas, applied to an in-memory copy of the source (the verbatim
source CSV on disk is never rewritten):

1. **Header names.** SCG 7 names the product hierarchy one level
   up from SCG 8. Renamed to the SCG 8 names the v8 driver reads:
     Solution Name     -> Product
     Solution Version  -> Product Version
     Product Name      -> Component          (VMware ESXi / VMware vCenter)
     Product Version   -> Component Version
     Feature/Component -> Feature/Function
   Every other header is already identical to SCG 8.
2. **"Undefined" baseline phrasing.** SCG 7 writes a baseline whose
   platform default is the hardened state as
   `Undefined (Defaults to X)`; SCG 8 writes the same meaning as
   `X or Undefined`, which is the form the adapter's evaluator
   recognizes (ControlEvaluator.allowsUndefined: an absent key is
   compliant, a present key is compared against X). Left untranslated,
   an absent key would be skipped instead of passed and an explicitly
   hardened key would compare against the literal sentence and FAIL.
   Rewritten to `X or Undefined` so the two versions score alike.
3. **Source token.** `source_ref` rows are tagged `SCG-7.0:`.

Deltas to the inherited read-recipe maps (same shape as the 9.1
driver's W1 fix: a recipe keyed on something that is spelled
differently in this version must be re-keyed, or the control silently
drops to informational or scores against the wrong literal):

4. **VGT, distributed-switch row.** The factory keys the
   `vlan_id_not` recipe for `dvpg.network-vgt` by SOURCE id
   (`vcenter-8.network-vgt`, `vcenter-9.network-vgt`) so that the
   ESX-side row sharing the control_id is not promoted. Added
   `vcenter-7.network-vgt` with the identical recipe; `esxi-7.network-vgt`
   stays informational exactly as `esxi-8.network-vgt` does.
5. **Discovery protocol expected value.** SCG 8 writes the baseline of
   `vds.network-restrict-discovery-protocol` as the enum string `none`,
   which the inherited `scalar:config.linkDiscoveryProtocolConfig.operation`
   recipe compares against directly. SCG 7 writes the same requirement
   ("deactivate CDP/LLDP") as the prose word `Deactivated`, which no
   switch ever reads back. Expected value pinned to `none` so a switch
   with discovery off scores compliant instead of failing forever.
6. **VM hardware version scored as a minimum (adapter build 57).**
   SCG 7's baseline for `vm.virtual-hardware` is `vmx-13 or newer`
   (its own title says "version 19 or newer"; the baseline column is
   what the canonical profile carries). Until build 56 the adapter
   compared `config.version` for exact equality, so this row shipped
   powercli_only. Build 57 compares the "or newer" phrasing as a floor
   (ControlEvaluator.VMX_MINIMUM), so the inherited recipe is kept and
   the factory's exact-equality caveat is replaced with the
   minimum-version caveat shared with the 9.1 driver.
7. **Key case of `esx.etc-issue`.** The SCG 7 source names the
   setting `Config.Etc.Issue`; the ESX advanced option (and every
   later SCG) is `Config.Etc.issue`. The adapter's option lookup is
   case-sensitive, so the wrong case made the control silently skip
   instead of evaluating. Corrected here. (Build 57 also lists the
   control for manual review because its expected value is prose, so
   the fix matters once site overrides exist.)
8. **Reset-port on the portgroup (adapter build 72).**
   `vds.network-reset-port` moves to DistributedVirtualPortgroup as
   `dvpg.network-reset-port` (its read is a portgroup-policy field; a
   distributed switch always read it as unreadable). Shared with the 8.0
   and 9.0 drivers: scripts/_adapter_deltas.py.
9. **Encryption and VAMI reads (adapter build 74).** Host encryption
   rows read `esxcli:system.settings.encryption.get` (the vim25
   `config.encryptionState` path does not exist); VAMI recipes fixed
   (`access/ssh:(value)`, `local-accounts/root`). See
   scripts/_adapter_deltas.py.
"""

from __future__ import annotations

import csv
import os
import re
import sys
import tempfile
from pathlib import Path

HEADER_RENAMES = {
    "Solution Name": "Product",
    "Solution Version": "Product Version",
    "Product Name": "Component",
    "Product Version": "Component Version",
    "Feature/Component": "Feature/Function",
}

_UNDEFINED_RE = re.compile(
    r"^\s*Undefined\s*\(\s*Defaults to\s+(.+?)\s*\)\s*$", re.IGNORECASE)


def translate_undefined(value: str) -> str:
    """`Undefined (Defaults to X)` -> `X or Undefined`; else unchanged."""
    m = _UNDEFINED_RE.match(value or "")
    if not m:
        return value
    return f"{m.group(1)} or Undefined"


def _factory_scripts_dir() -> Path:
    """The adapter repo is always cloned into a factory checkout at
    content/sdk-adapters/compliance/ (see bootstrap_managed_paks.sh);
    the shared normalizer modules live in the factory's scripts/."""
    here = Path(__file__).resolve()
    candidate = here.parents[4] / "scripts"
    if (candidate / "normalize_scg_v8.py").exists():
        return candidate
    raise SystemExit(
        "ERROR: cannot locate the factory's scripts/normalize_scg_v8.py "
        f"(looked in {candidate}). Run from an adapter clone inside a "
        "vcf-content-factory checkout."
    )


def main(argv: list) -> int:
    if len(argv) != 3:
        print("usage: normalize_scg_v70.py <input.csv> <output.csv>",
              file=sys.stderr)
        return 2

    sys.path.insert(0, str(_factory_scripts_dir()))
    import _compliance_normalize as base
    import normalize_scg_v8 as v8

    # Fail loud if the factory renames a patch target (a bare setattr
    # or dict edit would silently create a stale attribute and the run
    # would SUCCEED with plausible wrong output).
    for mod, name in ((v8, "SOURCE_TOKEN"),
                      (base, "_VIM_RECLASS_BY_SOURCE_ID"),
                      (base, "_VIM_RECLASS_BY_CONTROL_ID"),
                      (base, "write_canonical"),
                      (base, "CANONICAL_HEADER")):
        if not hasattr(mod, name):
            raise SystemExit(
                f"ERROR: factory module {mod.__name__} no longer has "
                f"'{name}'; update scripts/normalize_scg_v70.py before "
                "regenerating.")
    for key in ("vcenter-8.network-vgt",):
        if key not in base._VIM_RECLASS_BY_SOURCE_ID:
            raise SystemExit(f"ERROR: factory VGT recipe {key!r} moved; "
                             "update scripts/normalize_scg_v70.py.")
    for key in ("vds.network-restrict-discovery-protocol",
                "vm.virtual-hardware"):
        if key not in base._VIM_RECLASS_BY_CONTROL_ID:
            raise SystemExit(f"ERROR: factory reclass {key!r} moved; "
                             "update scripts/normalize_scg_v70.py.")
    if (not hasattr(base, "_VIM_RECLASS_DESCRIPTION_CAVEAT")
            or "vm.virtual-hardware"
            not in base._VIM_RECLASS_DESCRIPTION_CAVEAT):
        raise SystemExit("ERROR: factory caveat for vm.virtual-hardware "
                         "moved; update scripts/normalize_scg_v70.py.")

    # Delta 4: VGT recipe for the SCG 7 distributed-switch row.
    base._VIM_RECLASS_BY_SOURCE_ID["vcenter-7.network-vgt"] = (
        base._VIM_RECLASS_BY_SOURCE_ID["vcenter-8.network-vgt"])
    # Delta 5: SCG 7 "Deactivated" -> the enum string the recipe reads.
    dp = base._VIM_RECLASS_BY_CONTROL_ID[
        "vds.network-restrict-discovery-protocol"]
    base._VIM_RECLASS_BY_CONTROL_ID[
        "vds.network-restrict-discovery-protocol"] = dp[:3] + ("none",)
    # Delta 6: minimum-version caveat for vm.virtual-hardware.
    from normalize_scg_v91 import VMX_MINIMUM_CAVEAT
    base._VIM_RECLASS_DESCRIPTION_CAVEAT["vm.virtual-hardware"] = (
        VMX_MINIMUM_CAVEAT)

    with open(argv[1], encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        rows = list(reader)

    missing = [h for h in HEADER_RENAMES if h not in header]
    if missing:
        print(f"ERROR: {argv[1]} is not the SCG 7 layout; missing "
              f"{missing}", file=sys.stderr)
        return 2
    new_header = [HEADER_RENAMES.get(h, h) for h in header]
    baseline = new_header.index("Baseline Suggested Value")

    translated = 0
    for r in rows:
        if baseline < len(r):
            new = translate_undefined(r[baseline])
            if new != r[baseline]:
                r[baseline] = new
                translated += 1
    print(f"[normalize_scg_v70] baseline 'Undefined (Defaults to X)' "
          f"rewritten: {translated}", file=sys.stderr)

    fd, tmp = tempfile.mkstemp(suffix=".csv")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(new_header)
            w.writerows(rows)
        v8.SOURCE_TOKEN = "SCG-7.0"
        rc = v8.normalize(tmp, argv[2])
    finally:
        os.unlink(tmp)
    if rc != 0:
        return rc

    # Delta 7: ESX option key case for esx.etc-issue.
    with open(argv[2], encoding="utf-8", newline="") as f:
        out_rows = list(csv.DictReader(f))
    for r in out_rows:
        if (r["control_id"] == "esx.etc-issue"
                and r["parameter"] == "Config.Etc.Issue"):
            r["parameter"] = "Config.Etc.issue"
    # Delta 8: reset-port on the portgroup (scripts/_adapter_deltas.py).
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _adapter_deltas as deltas
    deltas.reset_port_to_portgroup(out_rows)
    # Delta 9: build-74 encryption (esxcli) and VAMI recipe fixes.
    got = deltas.build74(out_rows)
    if got != {"encryption": 1, "vami": 2}:
        raise SystemExit(f"ERROR: unexpected build-74 delta counts {got}")
    base.write_canonical(argv[2], out_rows)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
