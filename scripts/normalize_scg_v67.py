#!/usr/bin/env python3
"""Normalize the VMware vSphere SCG 6.7 source CSV to the canonical schema.

Usage (run from the factory checkout the adapter repo is cloned into,
AFTER profiles/canonical/scg_7.0.csv has been generated, because the
priority cross-check reads it):
  python3 scripts/normalize_scg_v67.py \
      profiles/vmware_scg_6.7.csv profiles/canonical/scg_6.7.csv

Source: profiles/vmware_scg_6.7.csv, converted verbatim from the
"vSphere 6.7" sheet of "VMware vSphere Security Configuration Guide
6.7 - Controls - 671-20210210-01.xlsx" by scripts/xlsx_to_csv.py.
The workbook's "Deprecated" sheet (one control retired from the
guide) is not part of the baseline and is not converted. Provenance
is recorded in CANONICAL_SCHEMA.md.

Why a standalone driver rather than a delta over the SCG 8 one: SCG
6.7 predates the `<product>-<version>.<slug>` source-ID scheme. Its
Guideline IDs (`ESXi.set-account-lockout`, `VM.disable-console-copy`,
`vNetwork.reject-forged-transmit-dvportgroup`) share no slugs with
7.0 and later, it has no Component, Implementation Priority, or
Setting Location column, and its baseline column is "Desired Value".
Deriving control_ids mechanically would give every 6.7 control a
different id from the same setting in 7.0/8.0/9.x.

So control_ids come from the curated ID_MAP below: each 6.7 Guideline
ID is mapped to the control_id the SAME setting carries in the newer
profiles, with the evidence tier recorded. A Guideline ID not in the
map fails the run (no silent fallback id). Controls with no newer
counterpart keep a 6.7-native id (`<prefix>.<6.7 slug, lowercased>`)
and are listed as UNMATCHED with the reason.

Once the control_id is fixed, the row goes through the same classifier
chain the SCG 8 driver runs (factory `_compliance_normalize.py`): the
generic parameter_kind classifier, the DVS/DVPG security-policy
classifier, then the control_id-keyed vim / esxcli / service_state /
control-override recipe maps. That is what makes a matched 6.7 control
read and score exactly like its newer counterpart.

6.7-specific rules (documented at the point of use below):

- priority: SCG 6.7 has no priority column. A matched control takes
  the priority of its nearest newer counterpart (7.0, else 8.0, 9.0,
  9.1); the source is recorded per row in ID_MAP and cross-checked at
  run time against the generated canonical profile, so a drift fails
  loud. Unmatched controls default to P2 (the pipeline's standard
  missing-priority fallback).
- advanced_setting rows whose parameter is a name pattern rather than
  a real key (`floppyX.present`, `scsiX:Y.mode`,
  `ethernetX.filterX.name = filtername`) can never resolve against the
  settings map, so they are demoted to manual_audit (same rule as the
  SCG 9.1 driver's delta 5).
- expected_value pins, where the 6.7 wording is prose and the
  inherited recipe reads an enum (see EXPECTED_PINS).
- a row the generic classifier calls vim_property but that ends up
  with no read recipe is written as powercli_only (unscored either
  way; this states it explicitly). Hits esx.ad-auth-proxy and
  esx.enable-strict-lockdown-mode.
"""

from __future__ import annotations

import csv
import re
import sys
from collections import Counter
from pathlib import Path

SOURCE_TOKEN = "SCG-6.7"

COL_ID = "Guideline ID"
COL_TITLE = "Description"
COL_DESCRIPTION = "Vulnerability Discussion"
COL_PARAMETER = "Configuration Parameter"
COL_EXPECTED = "Desired Value"
COL_ASSESSMENT = "PowerCLI Command Assessment"
COL_REMEDIATION = "PowerCLI Command Remediation"
REQUIRED_COLUMNS = [COL_ID, COL_TITLE, COL_DESCRIPTION, COL_PARAMETER,
                    COL_EXPECTED, COL_ASSESSMENT, COL_REMEDIATION]

PREFIX_TO_KIND = {
    "esx": "HostSystem",
    "vm": "VirtualMachine",
    "vds": "DistributedVirtualSwitch",
    "dvpg": "DistributedVirtualPortgroup",
}

# Evidence tiers.
PARAM = "same-parameter"   # identical Configuration Parameter key
SAME = "same-setting"      # same setting, parameter column absent/reworded
UNMATCHED = "unmatched"    # no newer control means the same thing

# 6.7 Guideline ID -> (control_id, tier, priority, priority source, note)
ID_MAP = {
    # --- same Configuration Parameter key as the newer control ---
    "ESXi.set-account-auto-unlock-time": ("esx.account-auto-unlock-time", PARAM, "P2", "SCG-7.0:esxi-7.account-auto-unlock-time", "Security.AccountUnlockTime"),
    "ESXi.set-account-lockout": ("esx.account-lockout", PARAM, "P2", "SCG-7.0:esxi-7.account-lockout", "Security.AccountLockFailures (6.7 baseline 3, 7.0 baseline 5)"),
    "ESXi.set-dcui-access": ("esx.lockdown-dcui-access", PARAM, "P2", "SCG-7.0:esxi-7.lockdown-dcui-access", "DCUI.Access"),
    "ESXi.set-dcui-timeout": ("esx.dcui-timeout", PARAM, "P2", "SCG-7.0:esxi-7.dcui-timeout", "UserVars.DcuiTimeOut"),
    "ESXi.set-password-policies": ("esx.account-password-policies", PARAM, "P0", "SCG-7.0:esxi-7.account-password-policies", "Security.PasswordQualityControl"),
    "ESXi.set-shell-interactive-timeout": ("esx.shell-interactive-timeout", PARAM, "P0", "SCG-7.0:esxi-7.shell-interactive-timeout", "UserVars.ESXiShellInteractiveTimeOut"),
    "ESXi.set-shell-timeout": ("esx.shell-timeout", PARAM, "P0", "SCG-7.0:esxi-7.shell-timeout", "UserVars.ESXiShellTimeOut"),
    "ESXi.TransparentPageSharing-intra-enabled": ("esx.transparent-page-sharing", PARAM, "P2", "SCG-7.0:esxi-7.transparent-page-sharing", "Mem.ShareForceSalting"),
    "ESXi.disable-mob": ("esx.deactivate-mob", PARAM, "P2", "SCG-7.0:esxi-7.deactivate-mob", "Config.HostAgent.plugins.solo.enableMob"),
    "ESXi.config-persistent-logs": ("esx.logs-persistent", PARAM, "P0", "SCG-7.0:esxi-7.logs-persistent", "Syslog.global.logDir"),
    "ESXi.enable-remote-syslog": ("esx.logs-remote", PARAM, "P0", "SCG-7.0:esxi-7.logs-remote", "Syslog.global.logHost"),
    "VM.disable-console-copy": ("vm.deactivate-console-copy", PARAM, "P2", "SCG-7.0:vm-7.deactivate-console-copy", "isolation.tools.copy.disable"),
    "VM.disable-console-paste": ("vm.deactivate-console-paste", PARAM, "P2", "SCG-7.0:vm-7.deactivate-console-paste", "isolation.tools.paste.disable"),
    "VM.disable-disk-shrinking-shrink": ("vm.deactivate-disk-shrinking-shrink", PARAM, "P2", "SCG-7.0:vm-7.deactivate-disk-shrinking-shrink", "isolation.tools.diskShrink.disable"),
    "VM.disable-disk-shrinking-wiper": ("vm.deactivate-disk-shrinking-wiper", PARAM, "P2", "SCG-7.0:vm-7.deactivate-disk-shrinking-wiper", "isolation.tools.diskWiper.disable"),
    "VM.disable-non-essential-3D-features": ("vm.deactivate-non-essential-3d-features", PARAM, "P0", "SCG-7.0:vm-7.deactivate-non-essential-3d-features", "mks.enable3d"),
    "VM.limit-setinfo-size": ("vm.limit-setinfo-size", PARAM, "P2", "SCG-7.0:vm-7.limit-setinfo-size", "tools.setInfo.sizeLimit"),
    "VM.restrict-host-info": ("vm.restrict-host-info", PARAM, "P2", "SCG-7.0:vm-7.restrict-host-info", "tools.guestlib.enableHostInfo"),
    "VM.TransparentPageSharing-inter-VM-Enabled": ("vm.transparentpagesharing-inter-vm-enabled", PARAM, "P2", "SCG-7.0:vm-7.transparentpagesharing-inter-vm-enabled", "sched.mem.pshare.salt"),
    "VM.verify-network-filter": ("vm.dvfilter", PARAM, "P2", "SCG-7.0:vm-7.dvfilter", "ethernetX.filterX.name (7.0: ethernet*.filter*.name)"),
    "vNetwork.enable-bpdu-filter": ("esx.network-bpdu", PARAM, "P0", "SCG-7.0:esxi-7.network-bpdu", "Net.BlockGuestBPDU"),
    "vNetwork.verify-dvfilter-bind": ("esx.network-dvfilter", PARAM, "P2", "SCG-7.0:esxi-7.network-dvfilter", "Net.DVFilterBindIpAddress"),
    # --- same setting, parameter column absent or worded differently ---
    "ESXi.Audit-SSH-Disable": ("esx.deactivate-ssh", SAME, "P2", "SCG-7.0:esxi-7.deactivate-ssh", "TSM-SSH service stopped"),
    "ESXi.disable-cim": ("esx.deactivate-cim", SAME, "P0", "SCG-7.0:esxi-7.deactivate-cim", "sfcbd-watchdog service stopped"),
    "ESXi.disable-slp": ("esx.deactivate-slp", SAME, "P2", "SCG-7.0:esxi-7.deactivate-slp", "slpd service stopped"),
    "ESXi.audit-exception-users": ("esx.lockdown-exception-users", SAME, "P2", "SCG-7.0:esxi-7.lockdown-exception-users", "lockdown Exception Users list"),
    "ESXi.enable-normal-lockdown-mode": ("esx.lockdown-mode", SAME, "P0", "SCG-7.0:esxi-7.lockdown-mode", "normal lockdown mode (7.0 baseline lockdownNormal)"),
    "ESXi.enable-auth-proxy": ("esx.ad-auth-proxy", SAME, "P0", "SCG-7.0:esxi-7.ad-auth-proxy", "vSphere Authentication Proxy for AD join"),
    "ESXi.enable-chap-auth": ("esx.iscsi-mutual-chap", SAME, "P0", "SCG-7.0:esxi-7.iscsi-mutual-chap", "bidirectional (mutual) iSCSI CHAP"),
    "ESXi.firewall-restrict-access": ("esx.firewall-restrict-access", SAME, "P1", "SCG-7.0:esxi-7.firewall-restrict-access", "firewall allowed-IP lists"),
    "ESXi.verify-acceptance-level-supported": ("esx.vib-acceptance-level-supported", SAME, "P2", "SCG-7.0:esxi-7.vib-acceptance-level-supported", "image profile acceptance level"),
    "ESXi.apply-patches": ("esx.updates", SAME, "P2", "SCG-7.0:esxi-7.updates", "host patched to current build"),
    "ESXi.config-ntp": ("esx.timekeeping-sources", SAME, "P0", "SCG-7.0:esxi-7.timekeeping-sources", "NTP servers configured (6.7 assessment lists NTP servers; weakest match in this map)"),
    "VM.verify-PCI-Passthrough": ("vm.pci-passthrough", SAME, "P0", "SCG-7.0:vm-7.pci-passthrough", "no PCI passthrough devices (6.7 key pciPassthru*.present)"),
    "vNetwork.reject-forged-transmit-dvportgroup": ("dvpg.network-reject-forged-transmit-dvportgroup", SAME, "P2", "SCG-7.0:vcenter-7.network-reject-forged-transmit-dvportgroup", "DVPG forged transmits Reject"),
    "vNetwork.reject-mac-changes-dvportgroup": ("dvpg.network-reject-mac-changes-dvportgroup", SAME, "P2", "SCG-7.0:vcenter-7.network-reject-mac-changes-dvportgroup", "DVPG MAC changes Reject"),
    "vNetwork.reject-promiscuous-mode-dvportgroup": ("dvpg.network-reject-promiscuous-mode-dvportgroup", SAME, "P2", "SCG-7.0:vcenter-7.network-reject-promiscuous-mode-dvportgroup", "DVPG promiscuous mode Reject"),
    "vNetwork.reject-forged-transmit-StandardSwitch": ("vds.network-reject-forged-transmit-standardswitch", SAME, "P2", "SCG-7.0:esxi-7.network-reject-forged-transmit-standardswitch", "standard switch forged transmits Reject"),
    "vNetwork.reject-mac-changes-StandardSwitch": ("vds.network-reject-mac-changes-standardswitch", SAME, "P2", "SCG-7.0:esxi-7.network-reject-mac-changes-standardswitch", "standard switch MAC changes Reject"),
    "vNetwork.reject-promiscuous-mode-StandardSwitch": ("vds.network-reject-promiscuous-mode-standardswitch", SAME, "P2", "SCG-7.0:esxi-7.network-reject-promiscuous-mode-standardswitch", "standard switch promiscuous mode Reject"),
    "vNetwork.restrict-netflow-usage": ("vds.network-restrict-netflow-usage", SAME, "P2", "SCG-7.0:vcenter-7.network-restrict-netflow-usage", "NetFlow/IPFIX off"),
    "vNetwork.restrict-port-level-overrides": ("dvpg.network-restrict-port-level-overrides", SAME, "P2", "SCG-7.0:vcenter-7.network-restrict-port-level-overrides", "DVPG port-level overrides blocked"),
    "vNetwork.limit-network-healthcheck": ("vds.vds-health-check-disable", SAME, "P2", "SCG-9.1:vcenter-9.vds-health-check-disable", "VDS health check off; no 7.0/8.0/9.0 counterpart, nearest is 9.1"),
    # --- no newer control means the same thing: 6.7-native ids ---
    "ESXi.config-snmp": ("esx.config-snmp", UNMATCHED, "P2", "default (unmatched)", "6.7 passes SNMP that is off OR properly configured; esx.deactivate-snmp (7.0+) requires the service stopped"),
    "ESXi.enable-ad-auth": ("esx.enable-ad-auth", UNMATCHED, "P2", "default (unmatched)", "join hosts to AD; no newer control requires AD membership"),
    "ESXi.enable-strict-lockdown-mode": ("esx.enable-strict-lockdown-mode", UNMATCHED, "P2", "default (unmatched)", "strict lockdown; esx.lockdown-mode (7.0+) baselines normal lockdown"),
    "VM.disable-independent-nonpersistent": ("vm.disable-independent-nonpersistent", UNMATCHED, "P2", "default (unmatched)", "no newer control for independent nonpersistent disks"),
    "VM.disconnect-devices-floppy": ("vm.disconnect-devices-floppy", UNMATCHED, "P2", "default (unmatched)", "one of three device controls folded into vm.remove-unnecessary-devices (7.0+); kept separate, not collapsed"),
    "VM.disconnect-devices-parallel": ("vm.disconnect-devices-parallel", UNMATCHED, "P2", "default (unmatched)", "one of three device controls folded into vm.remove-unnecessary-devices (7.0+); kept separate, not collapsed"),
    "VM.disconnect-devices-serial": ("vm.disconnect-devices-serial", UNMATCHED, "P2", "default (unmatched)", "one of three device controls folded into vm.remove-unnecessary-devices (7.0+); kept separate, not collapsed"),
    "VM.minimize-console-VNC-use": ("vm.minimize-console-vnc-use", UNMATCHED, "P2", "default (unmatched)", "RemoteDisplay.vnc.enabled; no newer control"),
}

# expected_value pins: 6.7 prose -> the value the inherited recipe reads.
EXPECTED_PINS = {
    # 6.7 "Enabled"; the scalar:config.lockdownMode recipe reads the
    # HostLockdownMode enum. Normal lockdown (the mapped control) is
    # "lockdownNormal", the same baseline 7.0/8.0 carry.
    "esx.lockdown-mode": "lockdownNormal",
}

# A settings key written as a pattern, not a literal key.
_PATTERN_PARAM = re.compile(r"(\*|[a-z]X\b|X\.|:Y|\s=\s|\s)")


def _factory_scripts_dir() -> Path:
    here = Path(__file__).resolve()
    candidate = here.parents[4] / "scripts"
    if (candidate / "_compliance_normalize.py").exists():
        return candidate
    raise SystemExit(
        "ERROR: cannot locate the factory's scripts/_compliance_normalize.py "
        f"(looked in {candidate}). Run from an adapter clone inside a "
        "vcf-content-factory checkout.")


def _check_priorities(canonical_dir: Path) -> None:
    """Fail loud if a recorded priority source no longer says what
    ID_MAP says it does (a regenerated newer profile changed it)."""
    cache = {}
    for gid, (cid, tier, prio, src, _note) in ID_MAP.items():
        if tier == UNMATCHED:
            continue
        token = src.split(":", 1)[0]            # e.g. SCG-7.0
        version = token.split("-", 1)[1]
        if version not in cache:
            path = canonical_dir / f"scg_{version}.csv"
            with open(path, encoding="utf-8", newline="") as f:
                cache[version] = list(csv.DictReader(f))
        hits = [r for r in cache[version]
                if r["control_id"] == cid and r["source_ref"] == src]
        if not hits:
            raise SystemExit(f"ERROR: priority source {src} for {gid} "
                             f"({cid}) not found in scg_{version}.csv")
        if hits[0]["priority"] != prio:
            raise SystemExit(
                f"ERROR: {gid}: ID_MAP priority {prio} but {src} is now "
                f"{hits[0]['priority']}; update ID_MAP.")


def normalize(input_path: str, output_path: str) -> int:
    sys.path.insert(0, str(_factory_scripts_dir()))
    import _compliance_normalize as base

    _check_priorities(Path(output_path).resolve().parent)

    with open(input_path, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        missing = [c for c in REQUIRED_COLUMNS
                   if c not in (reader.fieldnames or [])]
        if missing:
            base.log(f"ERROR: {input_path} missing required columns: "
                     f"{missing}")
            return 2
        src_rows = list(reader)

    unmapped = [(r.get(COL_ID) or "").strip() for r in src_rows
                if (r.get(COL_ID) or "").strip() not in ID_MAP]
    if unmapped:
        base.log(f"ERROR: Guideline IDs not in ID_MAP (add a mapping or an "
                 f"UNMATCHED entry): {unmapped}")
        return 2
    seen = [(r.get(COL_ID) or "").strip() for r in src_rows]
    stale = sorted(set(ID_MAP) - set(seen))
    if stale:
        base.log(f"ERROR: ID_MAP entries with no source row: {stale}")
        return 2

    out_rows = []
    by_kind: Counter = Counter()
    by_tier: Counter = Counter()
    demoted = []
    for src in src_rows:
        gid = src[COL_ID].strip()
        control_id, tier, priority, _psrc, _note = ID_MAP[gid]
        by_tier[tier] += 1
        prefix = control_id.split(".", 1)[0]
        resource_kind = PREFIX_TO_KIND[prefix]

        parameter = (src.get(COL_PARAMETER) or "").strip()
        if parameter.upper() in ("N/A", "NULL"):
            parameter = ""
        assessment = (src.get(COL_ASSESSMENT) or "").strip()
        title = (src.get(COL_TITLE) or "").strip()
        parameter_kind = base.classify_parameter_kind(parameter, assessment)

        # Same classifier chain, same order, as normalize_scg_v8.py.
        if resource_kind in ("DistributedVirtualSwitch",
                             "DistributedVirtualPortgroup"):
            secpol = base.classify_security_policy_param(
                assessment, gid, title)
            if secpol is not None:
                parameter = secpol
                parameter_kind = "vim_property"

        recipe = ""
        expected_override = None
        caveat = None
        rc = base.classify_vim_reclass(control_id)
        if rc is not None:
            parameter, recipe, expected_override, caveat = rc
            parameter_kind = "vim_property"
        ec = base.classify_esxcli_reclass(control_id)
        if ec is not None:
            parameter, recipe, expected_override, caveat = ec
            parameter_kind = "esxcli"
        sv = base.classify_service_state_reclass(control_id)
        if sv is not None:
            parameter, recipe, expected_override = sv
            parameter_kind = "vim_property"
            caveat = None
        si = base.classify_source_id_vim_reclass(gid)
        if si is not None:
            parameter, recipe, expected_override, caveat = si
            parameter_kind = "vim_property"
        co = base.classify_control_override(control_id)
        if co is not None:
            parameter, parameter_kind, expected_override, co_recipe = co
            recipe = co_recipe or ""
            caveat = None

        # 6.7 rule: the generic classifier reads some 6.7 multi-line
        # PowerCLI scripts (Get-VMHost | Get-View ... .Config.) as a
        # vim_property. With no read recipe that row is already
        # unscored; state it explicitly as powercli_only, the same
        # treatment the 7.0 driver gives vm.virtual-hardware.
        if not recipe:
            recipe = base.build_read_recipe(parameter, parameter_kind)
        if parameter_kind == "vim_property" and not recipe:
            parameter_kind = "powercli_only"
            parameter = ""

        # 6.7 rule: a pattern "key" can never resolve in the settings map.
        if (parameter_kind == "advanced_setting"
                and _PATTERN_PARAM.search(parameter)):
            parameter_kind = "manual_audit"
            demoted.append(control_id)

        expected = base.clean_expected_value(src.get(COL_EXPECTED) or "")
        if expected_override is not None:
            expected = expected_override
        if control_id in EXPECTED_PINS:
            expected = EXPECTED_PINS[control_id]

        description = (src.get(COL_DESCRIPTION) or "").strip()
        if caveat:
            description += caveat

        by_kind[parameter_kind] += 1
        out_rows.append({
            "control_id": control_id,
            "priority": priority,
            "resource_kind": resource_kind,
            "adapter_kind": base.ADAPTER_KIND,
            "parameter": parameter,
            "parameter_kind": parameter_kind,
            "value_type": base.infer_value_type(expected),
            "expected_value": expected,
            "title": title,
            "description": description,
            "source_ref": f"{SOURCE_TOKEN}:{gid}",
            "remediation_text": base.collapse_remediation(
                src.get(COL_REMEDIATION) or ""),
            "read_recipe": recipe,
        })

    written = base.write_canonical(output_path, out_rows)
    base.log(f"[normalize_scg_v67] in={len(src_rows)}  out={written}")
    base.log("  by match tier:")
    for k, v in sorted(by_tier.items()):
        base.log(f"    {v:5d}  {k}")
    if demoted:
        base.log(f"  pattern-key advanced_setting -> manual_audit: {demoted}")
    base.log("  by parameter_kind:")
    for k, v in sorted(by_kind.items()):
        base.log(f"    {v:5d}  {k}")
    return 0


def main(argv: list) -> int:
    if len(argv) != 3:
        print("usage: normalize_scg_v67.py <input.csv> <output.csv>",
              file=sys.stderr)
        return 2
    return normalize(argv[1], argv[2])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
