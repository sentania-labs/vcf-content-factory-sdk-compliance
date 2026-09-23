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
here (deltas 1-3 are the 9.1 format; deltas 4-5 close review
findings W1/W2 from
knowledge/context/reviews/compliance-scg-benchmark-set-2026-08-25.md;
delta 6 is adapter build 57):

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

6. **vm.virtual-hardware caveat.** The 9.1 baseline is
   `vmx-17 or higher`. Adapter build 57 compares that phrasing as a
   minimum (ControlEvaluator.VMX_MINIMUM: `vmx-M` passes iff M >= 17),
   so the factory's "exact equality only" caveat no longer describes
   this row. Replaced, for this run only, with the minimum-version
   caveat (VMX_MINIMUM_CAVEAT below, shared with the 7.0 driver).

7. **Encryption, VAMI and TLS (adapter build 74).** Applied to the
   output through scripts/_adapter_deltas.py: host encryption rows read
   `esxcli:system.settings.encryption.get`, the VAMI recipes are fixed,
   and `vc.tls-ciphers` expects `NIST_2024_TLS_13_ONLY` (the vendor 9.1
   baseline).

The deltas are applied by patching the imported factory modules
in-process (module-level constants and the shared COMPONENT_MAP /
SOURCE_ID_PREFIX_MAP dicts) rather than forking the 300-line driver.
If the factory normalizer grows native 9.1 support, this file
collapses to a two-line invocation.
"""

from __future__ import annotations

import re
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

    # Every patch below is guarded: if the factory renames the target
    # attribute, a bare setattr / dict-update would silently create a
    # stale attribute and the run would SUCCEED with plausible wrong
    # output (SCG-9.0 source tokens, unmapped sub-products). A factory
    # rename must fail this driver loudly instead (review W3).
    def _require(mod, name):
        if not hasattr(mod, name):
            raise SystemExit(
                f"ERROR: factory module {mod.__name__} no longer has "
                f"'{name}' — the 9.1 delta driver's patch target moved; "
                "update scripts/normalize_scg_v91.py before regenerating."
            )

    # Delta 1: 9.1 header shapes (no embedded newlines).
    for name in ("COL_COMPONENT", "COL_PRIORITY", "REQUIRED_COLUMNS",
                 "SOURCE_TOKEN", "COL_SCG_ID", "COL_TITLE",
                 "COL_DESCRIPTION", "COL_PARAMETER", "COL_EXPECTED",
                 "COL_ASSESSMENT", "COL_REMEDIATION",
                 "classify_parameter_kind"):
        _require(v9, name)
    for name in ("COMPONENT_MAP", "SOURCE_ID_PREFIX_MAP",
                 "_VIM_RECLASS_BY_CONTROL_ID", "classify_vim_reclass"):
        _require(base, name)

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

    # Delta 4 (review W1): upstream changed the Setting Location text of
    # `vcenter-9.network-reset-port` ("Distributed Switch Settings" ->
    # "UI: Distributed Port Group > ..."), so map_setting_location now
    # refines the row to DistributedVirtualPortgroup / control_id
    # `dvpg.network-reset-port` — and the 9.0-era reclass entry keyed
    # `vds.network-reset-port` no longer matches, silently dropping the
    # control to powercli_only. Add the DVPG-keyed entry with the same
    # recipe: `config.policy.portConfigResetAtDisconnect` is a
    # DVPortgroupConfigInfo.policy field, so DVPG is the more correct
    # target kind than 9.0's vds mapping anyway.
    base._VIM_RECLASS_BY_CONTROL_ID["dvpg.network-reset-port"] = (
        "config.policy.portConfigResetAtDisconnect",
        "bool",
        "config.policy.portConfigResetAtDisconnect",
        "true",   # SCG "Enabled" -> reset-at-disconnect must be ON
    )

    # Delta 5 (review W2): 9.1's assessment-text changes promote
    # `vc.smtp` / `vc.snmp` to advanced_setting, but their parameter
    # keys are not real OptionManager keys — a comma-joined multi-key
    # list ("mail.smtp.port, mail.smtp.username, ...") and a literal
    # placeholder ("snmp.receiver.<x>.enabled"). Such rows can never
    # resolve (every cycle hits the absent-key skip: safe, but dead
    # weight inflating the evaluable count). Demote them back to
    # manual_audit, mirroring the newline-joined multi-key rule the
    # factory classifier already applies.
    _orig_classify = v9.classify_parameter_kind

    def _classify_91(parameter, assessment_cmd):
        kind = _orig_classify(parameter, assessment_cmd)
        if kind == "advanced_setting" and parameter and (
                "," in parameter or re.search(r"<[^>]*>", parameter)):
            return "manual_audit"
        return kind

    v9.classify_parameter_kind = _classify_91

    # Delta 6: minimum-version caveat for vm.virtual-hardware.
    _require(base, "_VIM_RECLASS_DESCRIPTION_CAVEAT")
    if "vm.virtual-hardware" not in base._VIM_RECLASS_DESCRIPTION_CAVEAT:
        raise SystemExit("ERROR: factory caveat for vm.virtual-hardware "
                         "moved; update scripts/normalize_scg_v91.py.")
    base._VIM_RECLASS_DESCRIPTION_CAVEAT["vm.virtual-hardware"] = (
        VMX_MINIMUM_CAVEAT)

    rc = v9.normalize(argv[1], argv[2])
    if rc != 0:
        return rc

    # Delta 7 (adapter build 74): encryption rows to esxcli, VAMI recipe
    # fixes, and the vc.tls-ciphers expected value (scripts/_adapter_deltas.py).
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _adapter_deltas as deltas
    got = {}

    def _apply(rows):
        got.update(deltas.build74(rows))
        got["tls"] = deltas.tls_ciphers_91(rows)
        return 0

    deltas.rewrite(argv[2], base, _apply)
    if got != {"encryption": 3, "vami": 2, "tls": 1}:
        raise SystemExit(f"ERROR: unexpected build-74 delta counts {got}")
    return 0


# Shared with normalize_scg_v70.py (the two SCG versions whose baseline
# for vm.virtual-hardware is a floor: "vmx-13 or newer", "vmx-17 or higher").
VMX_MINIMUM_CAVEAT = (
    " [COVERAGE: this adapter reads config.version (e.g. \"vmx-21\") and "
    "scores the VM compliant when its hardware version is at or above the "
    "baseline minimum (the \"or newer\" / \"or higher\" floor), "
    "non-compliant below it. See UNAUDITED_CONTROLS.md.]"
)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
