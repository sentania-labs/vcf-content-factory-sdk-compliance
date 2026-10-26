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


# ---------------------------------------------------------------------------
# Build 74 deltas (knowledge/context/api-surface/
# compliance_config_encryption_and_vsan_checksum_reads.md and
# compliance_vami_appliance_api_read_path.md).
# ---------------------------------------------------------------------------

# Host configuration encryption: `config.encryptionState` is not a vim25
# field (HostConfigInfo has none; the data is HostRuntimeInfo.stateEncryption),
# so every host read these as unreadable. Switch to the SCG's own audit
# command, `esxcli system settings encryption get` (fields from the vendor
# SCG 9.1 audit script tools/audit-esx-9.ps1; not yet seen on the wire, so
# the esxcli reader matches field names case-insensitively). Template:
# esx.key-persistence. Expected values unchanged (TPM / true / true).
_ENCRYPTION = {
    "esx.tpm-configuration": ("encryption.Mode", "Mode"),
    "esx.secureboot-enforcement": ("encryption.RequireSecureBoot",
                                   "RequireSecureBoot"),
    "esx.tpm-trusted-binaries": (
        "encryption.RequireExecutablesOnlyFromInstalledVIBs",
        "RequireExecutablesOnlyFromInstalledVIBs"),
}


def encryption_to_esxcli(rows: List[Dict[str, str]]) -> int:
    """Rewrite the host encryption rows present in this profile to the
    esxcli recipe. Returns how many rows changed (0 is allowed: SCG 6.7 has
    none)."""
    n = 0
    for r in rows:
        spec = _ENCRYPTION.get(r["control_id"])
        if spec is None:
            continue
        if not r.get("read_recipe", "").startswith(
                "scalar:config.encryptionState.") and not r.get(
                "read_recipe", "").startswith("bool:config.encryptionState."):
            raise SystemExit(f"ERROR: {r['control_id']} read changed to "
                             f"{r.get('read_recipe')!r}; review the "
                             "encryption delta")
        r["parameter"] = spec[0]
        r["parameter_kind"] = "esxcli"
        r["read_recipe"] = "esxcli:system.settings.encryption.get:" + spec[1]
        n += 1
    return n


# vCenter appliance (VAMI) recipe fixes, keyed by control_id -> new
# (parameter, read_recipe). Evidence: the vendor spec
# reference/docs/vcenter-9.1.1-appliance-api.json.
#  - access/ssh returns a bare boolean body: read it with the value-only
#    token `(value)` (a `:enabled` field lookup on a boolean never resolves).
#  - local-accounts/policy does not exist (it matched local-accounts/{username}
#    for a user named "policy", a 404); the SCG control is about the ROOT
#    account: local-accounts/root, field max_days_between_password_change.
#    The spec says "If unset, password never expires"; build 76 reads an
#    absent field in a successful response as -1 (`?absent=-1`, the SCG's
#    own "never expires" expected value). HTTP failures stay unreadable.
#  - FIPS lives at system/global-fips (not system/security/global-fips).
_VAMI_RECIPES = {
    "vc.ssh": ("vami.access.ssh", "vami:access/ssh:(value)"),
    "vc.vami-access-ssh": ("vami.access.ssh", "vami:access/ssh:(value)"),
    "vc.vami-password-max-age": (
        "vami.local-accounts.root.max-days-between-password-change",
        "vami:local-accounts/root:max_days_between_password_change?absent=-1"),
    "vc.vami-administration-password-expiration": (
        "vami.local-accounts.root.max-days-between-password-change",
        "vami:local-accounts/root:max_days_between_password_change?absent=-1"),
    "vc.fips-enable": ("vami.system.global-fips.enabled",
                       "vami:system/global-fips:enabled"),
}


def vami_recipes(rows: List[Dict[str, str]]) -> int:
    """Apply the VAMI recipe fixes to the rows present in this profile."""
    n = 0
    for r in rows:
        spec = _VAMI_RECIPES.get(r["control_id"])
        if spec is None:
            continue
        if r.get("parameter_kind") != "vami_api":
            raise SystemExit(f"ERROR: {r['control_id']} is no longer "
                             "vami_api; review the VAMI delta")
        r["parameter"], r["read_recipe"] = spec
        n += 1
    return n


def tls_ciphers_91(rows: List[Dict[str, str]]) -> int:
    """SCG 9.1 only: vc.tls-ciphers expected value. The vendor SCG 9.1
    source (profiles/vmware_scg_9.1.csv, row vcenter-9.tls-ciphers,
    "Baseline Suggested Value") is NIST_2024_TLS_13_ONLY, as is its
    remediation command; the factory normalizer wrote NIST_2024 (the SCG
    8.0 / 9.0 baseline, which stays)."""
    n = 0
    for r in rows:
        if r["control_id"] == "vc.tls-ciphers":
            r["expected_value"] = "NIST_2024_TLS_13_ONLY"
            n += 1
    if n != 1:
        raise SystemExit("ERROR: expected one vc.tls-ciphers row in 9.1")
    return n


def build74(rows: List[Dict[str, str]]) -> Dict[str, int]:
    """Apply the build-74 deltas common to 7.0 / 8.0 / 9.0 / 9.1."""
    return {"encryption": encryption_to_esxcli(rows),
            "vami": vami_recipes(rows)}


# ---------------------------------------------------------------------------
# Build 98 deltas (review of build 97, W2; W3 removed in build 100).
# ---------------------------------------------------------------------------

# W2: the vendor's command for the VAMI root password expiration controls
# sets the appliance's GLOBAL local-accounts policy
# (com.vmware.appliance.local_accounts.policy). The adapter reads the ROOT
# account's own field (local-accounts/root max_days_between_password_change,
# see _VAMI_RECIPES), and nothing shows the policy rewrites an existing
# account. The vendor's own 9.0 / 9.1 tooling sets the policy to 9999, not
# the -1 its CSV gives. The vendor documents no root-account command, so the
# recommendation falls back to the generator's "no remediation command" text
# rather than a fix that may leave the alert open.
_UNPROVEN_REMEDIATION = {
    "vc.vami-password-max-age":
        '(Get-CisService -Name "com.vmware.appliance.local_accounts.policy")'
        '.set(@{max_days=-1})',
    "vc.vami-administration-password-expiration":
        '(Get-CisService -Name "com.vmware.appliance.local_accounts.policy")'
        '.set(@{max_days=-1})',
}


def drop_unproven_remediation(rows: List[Dict[str, str]]) -> int:
    """Blank (N/A) the remediation of the controls in _UNPROVEN_REMEDIATION.

    Only the exact vendor text is replaced; any other text fails the run so
    a changed vendor command is reviewed, not silently dropped. Returns the
    number of rows changed (0 is allowed: 7.0 and 9.1 carry no command)."""
    n = 0
    for r in rows:
        bad = _UNPROVEN_REMEDIATION.get(r["control_id"])
        if bad is None:
            continue
        text = r.get("remediation_text", "").strip()
        if text in ("", "N/A"):
            continue
        if text != bad:
            raise SystemExit(f"ERROR: {r['control_id']} remediation changed "
                             f"to {text!r}; review the build-98 W2 delta")
        r["remediation_text"] = "N/A"
        n += 1
    return n


def build98(rows: List[Dict[str, str]]) -> Dict[str, int]:
    """Apply the build-98 deltas (8.0 / 9.0 / 9.1). The W3 comment strip
    was removed in build 100: factory #254 makes the shared normalizer
    keep PowerShell comments as inline block comments."""
    return {"unproven_remediation": drop_unproven_remediation(rows)}
