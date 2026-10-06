# Scoring, data keys and alerts

The detail behind the README: how an object's benchmark is chosen, how
it is scored, every key the pack pushes, and the alerts it raises. For
installation see [installing.md](installing.md); for how the pack works
inside see [overview.md](overview.md).

## Adapter instance settings

| Field | Required | Default | Description |
|---|---|---|---|
| vCenter Host / IP | Yes | - | vCenter FQDN or IP |
| Username | Yes | - | vCenter SSO credentials |
| Password | Yes | - | vCenter SSO credentials |
| Compliance Profile | Yes | Auto (by version) | Auto (by version), VMware_SCG_6.7, VMware_SCG_7.0, VMware_SCG_8.0, VMware_SCG_9.0, VMware_SCG_9.1, or Custom |
| Custom Profile CSV Path | No | - | Filesystem path to CSV if Custom |
| Allow Insecure SSL | No | false | Accept self-signed certificates |
| Read vCenter appliance settings | No | false | Read the vCenter appliance (VAMI) settings (SSH, NTP, syslog, TLS profile, root password expiry, FIPS). Off: those controls are reported for manual review. On: needs the collection account in the vsphere.local SSO group `SystemConfiguration.Administrators`, which also grants appliance write access (no read-only appliance role exists) |

**Existing instances keep their stored profile on upgrade.** VCF Ops
stores the configured value on each adapter instance, and a pak upgrade
does not rewrite it (the new default applies to new instances only). An instance stored as a fixed `VMware_SCG_9.1`, for example, keeps scoring
every object against SCG 9.1 until someone edits it to `Auto (by version)`. An instance with no stored value keeps the pre-v3
fallback, SCG 8.0.

## Benchmark selection

- **Auto (by version):** hosts by their ESX version, VMs by their host's
  ESX version, and vCenter, clusters, distributed switches and portgroups
  by the vCenter version (a distributed switch's own version is not used).
  `major.minor` picks SCG 6.7, 7.0, 8.0, 9.0 or 9.1 (8.0 U3 is 8.0). A
  readable version with no bundled SCG gets no benchmark:
  `profile_name` = `no benchmark for ESX 10.0`, `no_benchmark` = 1,
  counters zeroed, no score.
- **Version the adapter could not read:** never a guess and never "no
  benchmark". The object is scored against the SCG it had last cycle; with
  no previous SCG (e.g. right after a collector restart) nothing was
  collected: `profile_name` = `benchmark unknown: ESX version unreadable`,
  score 0, `non_compliant` = 1, `collection_failed` = 1 (raises
  "Compliance data not collected").
- **Fixed profile:** that SCG for every object regardless of version.
- **Custom:** a canonical-schema CSV on the collector, for every object.

## Benchmark profiles

Bundled profiles ship with the pak under `profiles/canonical/`:
- `scg_6.7.csv`: vSphere Security Configuration Guide 6.7
- `scg_7.0.csv`: vSphere Security Configuration Guide 7
- `scg_8.0.csv`: VMware Security Configuration Guide for vSphere 8.x
- `scg_9.0.csv`: VMware Cloud Foundation 9.0 Security Configuration Guide
- `scg_9.1.csv`: VMware Cloud Foundation 9.1 Security Configuration Guide

All derive from vmware/vcf-security-and-compliance-guidelines (6.7 and
7.0 from its history; source CSVs kept beside them under `profiles/`;
the canonical form is produced by the normalizer pipeline, see
CANONICAL_SCHEMA.md). `profiles/manual_review.csv` lists controls that
are reported for manual review and never scored: those whose SCG expected
value is prose (site-specific text), and (build 70) the standard-switch
security controls, which live on each ESX host's vSwitches and were
wrongly read from the distributed switch. The file is required: a pak
without it fails to load rather than scoring those controls.

Custom profiles must follow the canonical CSV schema
(CANONICAL_SCHEMA.md). Upload the CSV to the VCF Ops appliance and
reference the path.

## Keys pushed onto VMWARE resources

Per-control (on the object the control applies to):
```
VCF-CF Compliance|<control_id>|Actual        property
VCF-CF Compliance|<control_id>|Expected      property
VCF-CF Compliance|<control_id>|Description   property
VCF-CF Compliance|<control_id>|Compliant     metric: 1 compliant, 0 non-compliant,
                                             -1 not evaluated (unreadable, or no
                                             longer in the applied benchmark)
```

Per object:
```
VCF-CF Compliance|profile_name       property: benchmark applied, or "no benchmark for ..."
VCF-CF Compliance|score              0-100%: pass / (pass + fail + unreadable); unreadable
                                     counts as failing; 0 when every control was unreadable;
                                     not pushed only when nothing was attempted
VCF-CF Compliance|pass_count         controls that passed
VCF-CF Compliance|fail_count         controls evaluated and failed (unreadable NOT included)
VCF-CF Compliance|total_count        pass + fail (0 when nothing was evaluated)
VCF-CF Compliance|unreadable_count   not pushed when the governing version cannot be read
VCF-CF Compliance|non_compliant      1 when fail_count > 0 or unreadable_count > 0
VCF-CF Compliance|no_benchmark       1 when the version has no SCG
VCF-CF Compliance|collection_failed  1 when nothing could be read on the object (every attempted
                                     control unreadable, or its version unreadable with no
                                     previous SCG); 0 otherwise; pushed every cycle
```

Per vCenter (on each VMWARE `VMwareAdapter Instance`), `<K>` in `All`,
`Host`, `VM`, `vCenter`, `Cluster`, `vDS`, `Portgroup`:
```
VCF-CF Compliance|Rollup|<K>|scored
VCF-CF Compliance|Rollup|<K>|non_compliant
VCF-CF Compliance|Rollup|<K>|no_benchmark
VCF-CF Compliance|Rollup|<K>|score_sum
VCF-CF Compliance|Rollup|<K>|avg_score        only when scored > 0
VCF-CF Compliance|Rollup|incomplete           0/1, every cycle: 1 when an inventory listing
                                               failed and rollup keys were held back
VCF-CF Compliance|Rollup|Benchmark|<B>|objects B in SCG_6.7, SCG_7.0, SCG_8.0,
                                               SCG_9.0, SCG_9.1, none, unknown
                                               (+ Custom)
```

**Unreadable counts as failing (build 63, owner decision).** A setting the
adapter could not read is counted against the score like a failure, so an
object whose every setting was unreadable scores 0. It is not a violation:
`fail_count` does not include it, its `Compliant` is -1 (no per-control
alert), and `unreadable_count` carries it separately. Instead each kind has
a "Compliance data not collected" alert (see Alerts). `score` and
`avg_score` are not pushed only when nothing was attempted (a no-benchmark
object, a non-vSAN cluster); VCF Ops then keeps showing the last value it
had, so read them with `total_count` / `unreadable_count` / `no_benchmark`
(per object) and `scored` (per vCenter, pushed every cycle).

## Keys on the pack's Compliance World

The Compliance World is one object shared by every adapter instance. The
adapter pushes one key onto it; the environment totals are computed by
VCF Operations, not pushed (build 82):
```
Summary|last_scan_timestamp          property, pushed: last scan by any instance
Rollup|Environment|scored            sum of every vCenter's VCF-CF Compliance|Rollup|All|scored
Rollup|Environment|non_compliant     sum of every vCenter's VCF-CF Compliance|Rollup|All|non_compliant
Rollup|Environment|no_benchmark      sum of every vCenter's VCF-CF Compliance|Rollup|All|no_benchmark
Rollup|Environment|avg_score         % : summed Rollup|All|score_sum / summed Rollup|All|scored
```

- **Engine-computed.** The four `Rollup|Environment` keys are
  `ComputedMetrics` declared on the ComplianceWorld kind in
  `describe.xml`. VCF Operations evaluates them over the Compliance
  World's `VMWARE / VMwareAdapter Instance` children (the vCenters), the
  same way it fills vSphere World's summary counts. No adapter instance
  writes them, so instances cannot overwrite each other's totals, which is
  why per-instance numbers were never pushed onto the world after build 57.
- **No policy enablement** is needed for them.
- **One collection interval behind.** The engine computes them from the
  per-vCenter values already stored, so they trail `Rollup|All|*` by one
  interval. One point is skipped on every pak upgrade.
- **`avg_score` is weighted** (summed `score_sum` over summed `scored`),
  not an average of per-vCenter averages. With nothing scored anywhere it
  is expected to have no data (0 over 0; not yet observed on a live
  instance) while `non_compliant` reads 0, so read `non_compliant` with
  `scored`.
- **The parent/child link.** Each adapter instance, every cycle, makes its
  own vCenter's `VMwareAdapter Instance` a child of the Compliance World
  through an additive Suite API relationship add (it never replaces the
  links other instances made). The link is never removed: a vCenter whose
  compliance adapter instance is deleted stays a child of the Compliance
  World, and whether its last rollup values keep counting in the totals
  has not been observed yet.

## Dashboards

The pak installs four dashboards (plus their eight views):

| Dashboard | What it is for |
|---|---|
| [VCF Content Factory] Compliance Environment Overview | The landing page: environment score, non-compliant objects and objects without a benchmark, compliance by vCenter and object type, objects per SCG version, the score trend, and open compliance alerts. |
| [VCF Content Factory] Compliance ESX Hosts | Pick a scope (vSphere World or one vCenter), see its hosts worst first with score and applied SCG, select a host to see its failing controls and their runbooks (that panel is currently empty, issue #30). |
| [VCF Content Factory] Compliance VMs | The same flow for VMs, built for thousands of objects (sorted list and totals, no heatmap). |
| [VCF Content Factory] Compliance vCenter & Networking | One page for the low-count kinds: vCenter, cluster, distributed switch and distributed portgroup lists, worst first, with the selected object's failing controls. |

The Environment Overview's four score tiles and its score trend read the
Compliance World's `Rollup|Environment|*` keys (above); no widget needs
policy enablement. The Objects Scored tile sits beside Non-Compliant
Objects so that a 0 non-compliant reading is always shown with its
denominator: 0 non-compliant with 0 scored means nothing was evaluated,
not all clear.

Builds 61 to 85 bundled four super metrics on `vSphere World` for those
tiles ("[VCF Content Factory] Compliance Average Score", "... Non-Compliant
Objects", "... Objects Scored", "... Objects Without Benchmark"). Build 86
retires them. The pak upgrade removes them from the instance, so there
is nothing to clean up by hand; the dashboard that read them is
re-imported by the same upgrade and reads ComplianceWorld instead.

## Alerts

Every alert name starts with `VCF Content Factory Compliance Alert: `
(build 86; alert ids unchanged, so an upgrade renames in place). Symptom
and recommendation names carry no prefix.

- `VCF Content Factory Compliance Alert: Host Compliance Score Degraded`
  (HostSystem, score below 95 / 80).
- One compliance alert per scored SCG control, named
  `VCF Content Factory Compliance Alert: <control_id>: <title>`, raised
  when that control's `Compliant` is 0,
  with the SCG remediation as its recommendation. Severity follows the
  SCG priority: P0 Critical, P1 Immediate, P2 Warning. Generated from the
  profiles by `scripts/generate_compliance_alerts.py`; never hand-edit
  the generated blocks in `describe.xml` or `resources.properties`.

- One "Compliance data not collected (<kind>)" alert per object kind
  (ESX host, VM, vCenter, cluster, distributed switch, distributed
  portgroup), severity Immediate, raised when `unreadable_count` > 0 (the
  adapter could not read some settings, and they count as failing in the
  score) OR `collection_failed` = 1 (nothing could be read at all,
  including an object whose version could not be read). Its recommendation explains the causes
  (connectivity, permissions, read method not supported on this version),
  where to see which settings (`unreadable_count`, and the controls whose
  `Compliant` is -1 with Actual "(unreadable)"), and what to check. Alert
  ids `vcfcf_compliance_collection_{host,vm,vcenter,cluster,vds,portgroup}`.

All compliance alerts are type Compliance (subType 21).

Wait and cancel cycles (build 86): the per-control alerts and the score
alert, and their symptoms, raise after 1 cycle and cancel after 3
consecutive cycles without the condition, so one cycle in which a failing
control could not be read (`Compliant` -1) does not close the finding. A
fixed control therefore clears its alert after 3 cycles (15 minutes at the
5 minute default). The collection alerts raise and cancel after 1 cycle.

## Limitations

- No remediation actions.
- Controls the adapter cannot read over vim25 / esxcli / VAMI are
  informational; see `profiles/UNAUDITED_CONTROLS.md`.
- Most SCG cluster (vSAN) controls need the vSAN Management SDK, which is
  not on the adapter classpath.
