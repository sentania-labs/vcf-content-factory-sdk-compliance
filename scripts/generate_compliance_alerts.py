#!/usr/bin/env python3
"""Generate the per-control compliance alerts from the canonical profiles.

Usage (from the adapter repo root):
  python3 scripts/generate_compliance_alerts.py          # rewrite in place
  python3 scripts/generate_compliance_alerts.py --check  # exit 1 if stale

Standard library only. Deterministic: the same profiles always produce
byte-identical output, so `--check` is a reproducibility gate.

What it writes (only between the GENERATED markers; everything outside
the markers, including the hand-written score symptoms and alert, is
left untouched):

  describe.xml
    <SymptomDefinitions>   one symptom per (resource kind, scored control)
    <AlertDefinitions>     one alert per scored control
    <Recommendations>      one recommendation per scored control
  resources/resources.properties
    the nameKey strings for all three

Rules (mirrored from the adapter so no alert exists for a control the
adapter never pushes):

* A control is SCORED in a profile when it is evaluable
  (advanced_setting always; vim_property / esxcli / vami_api only with a
  read_recipe), its parameter is not empty / N/A / multi-line, its
  parameter_kind is one the collector for its resource kind reads
  (BenchmarkSelector.evaluatedFor), and profiles/manual_review.csv does
  not demote it for that profile.
* The set of alerted controls is the union of scored controls across the
  bundled profiles (SCG 6.7, 7.0, 8.0, 9.0, 9.1).
* Symptom: metric condition `VCF-CF Compliance|<control_id>|Compliant = 0`
  on the VMWARE resource kind (Compliant is pushed as a metric: 1
  compliant, 0 non-compliant, -1 not evaluated; -1 never fires).
* Alert: type 15, subType 21 (COMPLIANCE), impact badge risk, severity
  Automatic (taken from the symptom). Name "<control_id>: <title>".
* Symptom severity from the SCG priority: P0 Critical, P1 Immediate,
  P2 Warning.
* Collection alerts (build 63, owner decision "If unreadable = not
  collected/etc, let's count it as failing, but can we tell the user it's
  failing to collect?"): one alert per resource kind (6), type 15
  subType 21, impact badge risk, all six sharing one recommendation that
  explains what unreadable means and what to check. Each alert fires on
  either of two Immediate symptoms (build 65): `VCF-CF
  Compliance|unreadable_count > 0` (some settings unreadable) OR `VCF-CF
  Compliance|collection_failed = 1` (nothing could be read, including a
  version that could not be read). Ids use the
  `vcfcf_compliance_collection_` prefix, distinct from the per-control
  `vcfcf_compliance_ctl_` ids. nameKeys from 2000.
* Title, priority and remediation come from the NEWEST profile in which
  the control is scored. If that row has no usable remediation text
  (empty or N/A), the next-newest scored row with one is used. When the
  remediation text differs across the scored versions, the
  recommendation says which SCG version it is from.
"""

from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DESCRIBE = REPO / "describe.xml"
PROPERTIES = REPO / "resources" / "resources.properties"
CANONICAL = REPO / "profiles" / "canonical"
MANUAL_REVIEW = REPO / "profiles" / "manual_review.csv"

# Oldest first. (profile name, canonical file, SCG label)
PROFILES = [
    ("VMware_SCG_6.7", "scg_6.7.csv", "SCG 6.7"),
    ("VMware_SCG_7.0", "scg_7.0.csv", "SCG 7.0"),
    ("VMware_SCG_8.0", "scg_8.0.csv", "SCG 8.0"),
    ("VMware_SCG_9.0", "scg_9.0.csv", "SCG 9.0"),
    ("VMware_SCG_9.1", "scg_9.1.csv", "SCG 9.1"),
]

# Canonical resource_kind token -> (Ops resource kind key, kinds read).
# Parameter kinds per collector mirror BenchmarkSelector.evaluatedFor.
KINDS = {
    "HostSystem": ("HostSystem",
                   {"advanced_setting", "vim_property", "esxcli"}),
    "VirtualMachine": ("VirtualMachine",
                       {"advanced_setting", "vim_property", "esxcli"}),
    "VCenterAdapterInstance": ("VMwareAdapter Instance",
                               {"advanced_setting", "vami_api"}),
    "ClusterComputeResource": ("ClusterComputeResource",
                               {"vim_property", "esxcli"}),
    "DistributedVirtualSwitch": ("VmwareDistributedVirtualSwitch",
                                 {"vim_property", "esxcli"}),
    "DistributedVirtualPortgroup": ("DistributedVirtualPortgroup",
                                    {"vim_property", "esxcli"}),
}
KIND_ORDER = list(KINDS)

SEVERITY = {"P0": "Critical", "P1": "Immediate", "P2": "Warning"}

NAMEKEY_BASE = 1000   # generated nameKeys: 1000 + 3*i (+0 sym, +1 alert, +2 rec)
COLLECTION_NAMEKEY_BASE = 2000   # 2000 + 2*i (+0 sym, +1 alert); rec 2100
COLLECTION_FAILED_NAMEKEY_BASE = 2020   # 2020 + i: collection_failed symptoms

# Per-kind "Compliance data not collected" alerts (build 63).
# canonical resource_kind -> (id slug, label used in names)
COLLECTION_KINDS = [
    ("HostSystem", "host", "ESX host"),
    ("VirtualMachine", "vm", "VM"),
    ("VCenterAdapterInstance", "vcenter", "vCenter"),
    ("ClusterComputeResource", "cluster", "cluster"),
    ("DistributedVirtualSwitch", "vds", "distributed switch"),
    ("DistributedVirtualPortgroup", "portgroup", "distributed portgroup"),
]
COLLECTION_REC_ID = "vcfcf_compliance_collection_check"
COLLECTION_REC_TEXT = (
    "The compliance adapter could not read one or more security settings on "
    "this object, so they were not collected and count as failing in its "
    "compliance score (they are not reported as violations, and raise no "
    "per-control alert). Common causes: the object or its ESX host is "
    "disconnected or not responding in vCenter; the adapter's vCenter "
    "account lacks read permission for the setting; or the read method is "
    "not supported on this product version. If the object's product "
    "version itself could not be read, nothing was collected: the object "
    "scores 0 and collection_failed is 1. To see which settings: open "
    "the object's VCF-CF Compliance metrics; unreadable_count gives the "
    "number, and each control whose Compliant value is -1 with Actual "
    "\"(unreadable)\" is one of them (the compliance dashboards' object "
    "lists show the count in their Unreadable column). Check the object's "
    "connection state in vCenter, the adapter account's permissions "
    "(read-only at the vCenter root, propagated to children), and the "
    "adapter log for read errors naming this object (the log also gives, "
    "once per cycle, a count of unreadable settings by reason). For the "
    "vCenter appliance settings (read only when the instance's \"Read "
    "vCenter appliance settings\" option is on), the account must be in "
    "the vsphere.local SSO group SystemConfiguration.Administrators; that "
    "group also grants appliance WRITE access (there is no read-only "
    "appliance role), so decide whether that trade-off is acceptable before "
    "granting it, or turn the option off to report those settings for "
    "manual review. The alert clears on the first collection cycle in which "
    "every setting is read.")


def collection_failed_symptom_id(unreadable_sid: str) -> str:
    """Build 65: the collection_failed symptom paired with a kind's
    unreadable_count symptom."""
    return unreadable_sid[:-len("_unreadable")] + "_failed"


def collection_ids():
    """(canonical kind, Ops kind, symptom id, alert id, label) per kind."""
    out = []
    for kind, slug, label in COLLECTION_KINDS:
        out.append((kind, KINDS[kind][0],
                    f"vcfcf_compliance_collection_{slug}_unreadable",
                    f"vcfcf_compliance_collection_{slug}", label))
    return out

BEGIN = "BEGIN GENERATED by scripts/generate_compliance_alerts.py"
END = "END GENERATED by scripts/generate_compliance_alerts.py"


def load_manual_review() -> set:
    out = set()
    with MANUAL_REVIEW.open(encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            if r["profile"].strip() and r["control_id"].strip():
                out.add((r["profile"].strip(), r["control_id"].strip()))
    return out


def evaluable(r: dict) -> bool:
    pk = r["parameter_kind"]
    recipe = (r.get("read_recipe") or "").strip()
    if pk == "advanced_setting":
        return True
    if pk in ("vim_property", "esxcli", "vami_api"):
        return bool(recipe)
    return False


def scored(r: dict, profile: str, manual: set) -> bool:
    kind = KINDS.get(r["resource_kind"])
    if kind is None or not evaluable(r):
        return False
    if r["parameter_kind"] not in kind[1]:
        return False
    param = r["parameter"]
    if not param or param == "N/A" or "\n" in param:
        return False
    return (profile, r["control_id"]) not in manual


def usable_remediation(text: str) -> bool:
    t = (text or "").strip()
    return bool(t) and t.upper() not in ("N/A", "NA", "NONE")


def collect() -> list:
    manual = load_manual_review()
    # control_id -> list of (profile index, row), scored rows only
    rows: dict = {}
    for idx, (profile, fname, _label) in enumerate(PROFILES):
        with (CANONICAL / fname).open(encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                if scored(r, profile, manual):
                    rows.setdefault(r["control_id"], []).append((idx, r))
    controls = []
    for cid, versions in rows.items():
        kinds = {r["resource_kind"] for _, r in versions}
        if len(kinds) != 1:
            raise SystemExit(f"ERROR: {cid} is scored on more than one "
                             f"resource kind: {sorted(kinds)}")
        versions.sort(key=lambda t: t[0])
        newest_idx, newest = versions[-1]
        rem_idx, rem = None, ""
        for idx, r in reversed(versions):
            if usable_remediation(r["remediation_text"]):
                rem_idx, rem = idx, r["remediation_text"].strip()
                break
        distinct = {r["remediation_text"].strip() for _, r in versions
                    if usable_remediation(r["remediation_text"])}
        priority = newest["priority"].strip()
        if priority not in SEVERITY:
            raise SystemExit(f"ERROR: {cid} has unknown priority "
                             f"{priority!r}")
        controls.append({
            "control_id": cid,
            "resource_kind": newest["resource_kind"],
            "title": " ".join(newest["title"].split()),
            "priority": priority,
            "labels": [PROFILES[i][2] for i, _ in versions],
            "newest_label": PROFILES[newest_idx][2],
            "remediation": " ".join(rem.split()),
            "remediation_label": PROFILES[rem_idx][2] if rem_idx is not None
            else None,
            "remediation_differs": len(distinct) > 1,
        })
    controls.sort(key=lambda c: (KIND_ORDER.index(c["resource_kind"]),
                                 c["control_id"]))
    slugs = {}
    for c in controls:
        slug = re.sub(r"[^a-z0-9]+", "_", c["control_id"].lower()).strip("_")
        if slug in slugs:
            raise SystemExit(f"ERROR: id slug collision {slug!r}: "
                             f"{slugs[slug]} vs {c['control_id']}")
        slugs[slug] = c["control_id"]
        c["slug"] = slug
    return controls


def recommendation_text(c: dict) -> str:
    applies = ", ".join(c["labels"])
    if c["remediation_label"] is None:
        return (f"The Security Configuration Guide gives no remediation "
                f"command for {c['control_id']}. Review the control "
                f"description in the {c['newest_label']} guide and correct "
                f"the setting so that its Actual value matches Expected "
                f"(both are on the object under VCF-CF Compliance|"
                f"{c['control_id']}). Scored in: {applies}.")
    text = c["remediation"]
    if c["remediation_differs"]:
        others = ", ".join(x for x in c["labels"]
                           if x != c["remediation_label"])
        note = (f" (Remediation from {c['remediation_label']}, the newest "
                f"guide with a fix for this control. {others} word the fix "
                f"differently; the object's profile_name shows which guide "
                f"applies to it.)")
    else:
        note = f" (Source: {c['remediation_label']}. Scored in: {applies}.)"
    return text + note


def xml_attr(s: str) -> str:
    return (s.replace("&", "&amp;").replace('"', "&quot;")
            .replace("<", "&lt;").replace(">", "&gt;"))


def prop_value(s: str) -> str:
    """Java .properties value: ASCII only, backslash escaped."""
    out = []
    for ch in s.replace("\\", "\\\\"):
        if ord(ch) > 126 or ord(ch) < 32:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    v = "".join(out)
    if v.startswith(" "):
        v = "\\" + v
    return v


def render(controls: list):
    sym, alert, rec, props = [], [], [], []
    for i, c in enumerate(controls):
        nk = NAMEKEY_BASE + 3 * i
        ops_kind = KINDS[c["resource_kind"]][0]
        sid = f"vcfcf_compliance_ctl_{c['slug']}_noncompliant"
        aid = f"vcfcf_compliance_ctl_{c['slug']}"
        rid = f"vcfcf_compliance_ctl_{c['slug']}_fix"
        key = f"VCF-CF Compliance|{c['control_id']}|Compliant"
        sym.append(
            f'    <SymptomDefinition id="{sid}"\n'
            f'                       nameKey="{nk}"\n'
            f'                       adapterKind="VMWARE"\n'
            f'                       resourceKind="{xml_attr(ops_kind)}"\n'
            f'                       waitCycle="1"\n'
            f'                       cancelCycle="1">\n'
            f'      <State severity="{SEVERITY[c["priority"]]}">\n'
            f'        <Condition type="metric" key="{xml_attr(key)}"\n'
            f'                   operator="=" value="0"\n'
            f'                   valueType="numeric" thresholdType="static"/>\n'
            f'      </State>\n'
            f'    </SymptomDefinition>\n')
        alert.append(
            f'    <AlertDefinition id="{aid}"\n'
            f'                     nameKey="{nk + 1}"\n'
            f'                     adapterKind="VMWARE"\n'
            f'                     resourceKind="{xml_attr(ops_kind)}"\n'
            f'                     type="15" subType="21"\n'
            f'                     waitCycle="1" cancelCycle="1">\n'
            f'      <State severity="Automatic">\n'
            f'        <Impact type="badge" key="risk"/>\n'
            f'        <SymptomSet ref="{sid}" operator="and"\n'
            f'                    aggregation="any" applyOn="self" '
            f'negateCondition="false"/>\n'
            f'        <Recommendations>\n'
            f'          <Recommendation ref="{rid}" priority="1"/>\n'
            f'        </Recommendations>\n'
            f'      </State>\n'
            f'    </AlertDefinition>\n')
        rec.append(
            f'    <Recommendation key="{rid}">\n'
            f'      <Description nameKey="{nk + 2}"/>\n'
            f'    </Recommendation>\n')
        name = f"{c['control_id']}: {c['title']}"
        props.append(f"{nk}={prop_value(c['control_id'] + ' is not compliant')}")
        props.append(f"{nk + 1}={prop_value(name)}")
        props.append(f"{nk + 2}={prop_value(recommendation_text(c))}")
    for i, (_kind, ops_kind, sid, aid, label) in enumerate(collection_ids()):
        nk = COLLECTION_NAMEKEY_BASE + 2 * i
        sym.append(
            f'    <SymptomDefinition id="{sid}"\n'
            f'                       nameKey="{nk}"\n'
            f'                       adapterKind="VMWARE"\n'
            f'                       resourceKind="{xml_attr(ops_kind)}"\n'
            f'                       waitCycle="1"\n'
            f'                       cancelCycle="1">\n'
            f'      <State severity="Immediate">\n'
            f'        <Condition type="metric" '
            f'key="VCF-CF Compliance|unreadable_count"\n'
            f'                   operator="&gt;" value="0"\n'
            f'                   valueType="numeric" thresholdType="static"/>\n'
            f'      </State>\n'
            f'    </SymptomDefinition>\n')
        fsid = collection_failed_symptom_id(sid)
        fnk = COLLECTION_FAILED_NAMEKEY_BASE + i
        sym.append(
            f'    <SymptomDefinition id="{fsid}"\n'
            f'                       nameKey="{fnk}"\n'
            f'                       adapterKind="VMWARE"\n'
            f'                       resourceKind="{xml_attr(ops_kind)}"\n'
            f'                       waitCycle="1"\n'
            f'                       cancelCycle="1">\n'
            f'      <State severity="Immediate">\n'
            f'        <Condition type="metric" '
            f'key="VCF-CF Compliance|collection_failed"\n'
            f'                   operator="=" value="1"\n'
            f'                   valueType="numeric" thresholdType="static"/>\n'
            f'      </State>\n'
            f'    </SymptomDefinition>\n')
        props.append(f"{fnk}={prop_value('Compliance data collection failed on ' + label)}")
        alert.append(
            f'    <AlertDefinition id="{aid}"\n'
            f'                     nameKey="{nk + 1}"\n'
            f'                     adapterKind="VMWARE"\n'
            f'                     resourceKind="{xml_attr(ops_kind)}"\n'
            f'                     type="15" subType="21"\n'
            f'                     waitCycle="1" cancelCycle="1">\n'
            f'      <State severity="Automatic">\n'
            f'        <Impact type="badge" key="risk"/>\n'
            f'        <SymptomSets operator="or">\n'
            f'          <SymptomSet ref="{sid}" operator="and"\n'
            f'                      aggregation="any" applyOn="self" '
            f'negateCondition="false"/>\n'
            f'          <SymptomSet ref="{fsid}" operator="and"\n'
            f'                      aggregation="any" applyOn="self" '
            f'negateCondition="false"/>\n'
            f'        </SymptomSets>\n'
            f'        <Recommendations>\n'
            f'          <Recommendation ref="{COLLECTION_REC_ID}" priority="1"/>\n'
            f'        </Recommendations>\n'
            f'      </State>\n'
            f'    </AlertDefinition>\n')
        props.append(f"{nk}={prop_value('Compliance settings unreadable on ' + label)}")
        props.append(f"{nk + 1}={prop_value('Compliance data not collected (' + label + ')')}")
    rec.append(
        f'    <Recommendation key="{COLLECTION_REC_ID}">\n'
        f'      <Description nameKey="{COLLECTION_NAMEKEY_BASE + 100}"/>\n'
        f'    </Recommendation>\n')
    props.append(f"{COLLECTION_NAMEKEY_BASE + 100}={prop_value(COLLECTION_REC_TEXT)}")
    return "".join(sym), "".join(alert), "".join(rec), "\n".join(props) + "\n"


def splice(text: str, section: str, body: str, comment: tuple) -> str:
    open_c, close_c = comment
    begin = f"{open_c}{BEGIN}: {section}{close_c}"
    end = f"{open_c}{END}: {section}{close_c}"
    pat = re.compile(re.escape(begin) + r"\n.*?" + re.escape(end), re.S)
    if not pat.search(text):
        raise SystemExit(f"ERROR: markers for {section!r} not found")
    return pat.sub(lambda _m: begin + "\n" + body + end, text, count=1)


def main(argv: list) -> int:
    check = "--check" in argv[1:]
    controls = collect()
    sym, alert, rec, props = render(controls)

    xml_c = ("    <!-- ", " -->")
    describe_old = DESCRIBE.read_text(encoding="utf-8")
    describe_new = splice(describe_old, "symptoms", sym, xml_c)
    describe_new = splice(describe_new, "alerts", alert, xml_c)
    describe_new = splice(describe_new, "recommendations", rec, xml_c)

    props_old = PROPERTIES.read_text(encoding="utf-8")
    props_new = splice(props_old, "per-control alerts", props, ("# ", ""))

    by_kind: dict = {}
    by_sev: dict = {}
    for c in controls:
        by_kind[c["resource_kind"]] = by_kind.get(c["resource_kind"], 0) + 1
        s = SEVERITY[c["priority"]]
        by_sev[s] = by_sev.get(s, 0) + 1
    print(f"[generate_compliance_alerts] {len(controls)} scored controls -> "
          f"{len(controls)} symptoms, {len(controls)} alerts, "
          f"{len(controls)} recommendations", file=sys.stderr)
    print(f"[generate_compliance_alerts] by kind: "
          + ", ".join(f"{k}={by_kind[k]}" for k in KIND_ORDER if k in by_kind),
          file=sys.stderr)
    print(f"[generate_compliance_alerts] plus {len(collection_ids())} "
          f"collection alerts (unreadable_count > 0 OR collection_failed = 1; "
          f"{2 * len(collection_ids())} symptoms) and 1 shared collection "
          f"recommendation", file=sys.stderr)
    print(f"[generate_compliance_alerts] by severity: "
          + ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items())),
          file=sys.stderr)

    stale = describe_new != describe_old or props_new != props_old
    if check:
        if stale:
            print("[generate_compliance_alerts] STALE: describe.xml / "
                  "resources.properties differ from the profiles; run "
                  "scripts/generate_compliance_alerts.py", file=sys.stderr)
            return 1
        print("[generate_compliance_alerts] up to date", file=sys.stderr)
        return 0
    DESCRIBE.write_text(describe_new, encoding="utf-8")
    PROPERTIES.write_text(props_new, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
