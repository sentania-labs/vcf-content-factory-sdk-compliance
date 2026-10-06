# Overview — VCF Content Factory Compliance

## Stitched onto VMWARE resources (start here)

Almost everything this pack produces lives on objects the VMWARE (vSphere)
adapter already owns, not on the pack's own object. The generated
inventory tree shows only the pack's own `ComplianceWorld`, so use this
list to find the data:

| VMWARE object | What the pack pushes onto it |
|---|---|
| HostSystem, VirtualMachine, VMwareAdapter Instance (vCenter), ClusterComputeResource, VmwareDistributedVirtualSwitch, DistributedVirtualPortgroup | Per control: `VCF-CF Compliance\|<control_id>\|{Actual, Expected, Description}` (properties) and `...\|Compliant` (1 / 0 / -1 not evaluated). Per object: `profile_name`, `score`, `pass_count`, `fail_count`, `total_count`, `unreadable_count`, `non_compliant`, `no_benchmark`, `collection_failed` (1 when nothing could be read on the object). |
| VMwareAdapter Instance (vCenter) | Per-vCenter rollup: `VCF-CF Compliance\|Rollup\|<All, Host, VM, vCenter, Cluster, vDS, Portgroup>\|{scored, non_compliant, no_benchmark, score_sum, avg_score}`, and `Rollup\|Benchmark\|<SCG_6.7 ... SCG_9.1, none, unknown>\|objects`. |
| The same six kinds | 143 alert definitions, all type Compliance (subType 21): 136 per-control alerts, one per scored SCG control, named `VCF Content Factory Compliance Alert: <control_id>: <title>`, raised when that control's `Compliant` is 0, each with the SCG remediation as its recommendation; 6 "VCF Content Factory Compliance Alert: Compliance data not collected (<kind>)" alerts, one per kind, severity Immediate, raised when `unreadable_count` > 0 or `collection_failed` = 1, with a recommendation on what unreadable means and what to check; and 1 "VCF Content Factory Compliance Alert: Host Compliance Score Degraded" alert on HostSystem (score below 95 / 80). Every alert name starts with that prefix (build 86), so all of the pack's alerts sort and filter together. |

The full key list, with when each key is pushed, is in
[data-reference.md](data-reference.md) under "Keys pushed onto VMWARE resources".

The pack's own `ComplianceWorld` carries the environment totals,
`Rollup|Environment|{scored, non_compliant, no_benchmark, avg_score}`
(no `VCF-CF Compliance` group on the world), which VCF Operations computes from the per-vCenter rollups
(see "Resource kinds" below).

## What's in the Pack

VCF Content Factory Compliance is a Tier 2 (Java SDK) management pack that
evaluates ESX host, VM, vCenter, cluster (vSAN), distributed switch and
distributed portgroup configuration against the VMware Security
Configuration Guide (SCG) and reports per-control results, per-object
scores, per-vCenter rollups and per-control compliance alerts into VCF
Operations.

The adapter connects to a vCenter, walks the inventory over vSphere SOAP
(vim25), reads each host's effective configuration (vim properties,
advanced settings, esxcli service/firewall/account state, and the vCenter
appliance VAMI policy endpoints), and scores it against the active
profile. Results are pushed onto the existing VMWARE resources so an
operator sees compliance posture in-place on the hosts and vCenter they
already monitor — no separate object tree to navigate for per-control
detail.

Bundled profiles cover SCG 6.7, 7.0, 8.0, 9.0, and 9.1. The default,
`Auto (by version)`, scores each object against the SCG for its own
version (hosts by ESX version, VMs by their host's ESX version,
everything else by the vCenter version); an object whose version has no
bundled SCG is reported as "no benchmark" and not scored. A fixed SCG or
a custom canonical-schema CSV can be forced instead.

### Resource kinds

The adapter owns a single synthetic resource kind:

| Kind | Key | Purpose |
|------|-----|---------|
| Compliance World | `ComplianceWorld` | The environment-level object, one shared by every adapter instance: the environment compliance totals, and adapter liveness. |

The Compliance World carries two kinds of data:

- **`Summary|last_scan_timestamp`**, the last scan by any instance. This
  is the only key the adapter pushes onto the world.
- **The environment totals**, `Rollup|Environment|scored`,
  `non_compliant`, `no_benchmark` and `avg_score` (build 82; shown as
  Rollup, Environment in the metric browser).
  No adapter instance pushes these. They are declared as `ComputedMetrics`
  in `describe.xml`, and VCF Operations computes them by summing each
  vCenter's `VCF-CF Compliance|Rollup|All|*` keys across the Compliance
  World's `VMwareAdapter Instance` children. `avg_score` is the summed
  `score_sum` over the summed `scored`, a weighted average, never an
  average of per-vCenter averages. This is how VMWARE fills vSphere
  World's own summary counts.

Because no instance writes a total, any number of adapter instances can
share the world without overwriting each other (the reason per-instance
fleet numbers were moved off the world in build 57), and the totals need
**no policy enablement**. Two timing effects to expect: the totals trail
the per-vCenter rollups by one collection interval, because the engine
computes them from the values already stored; and one point is skipped on
every pak upgrade. With nothing scored anywhere, `non_compliant` sums to 0
and `avg_score` is expected to have no data (0 over 0, not yet observed on
a live instance), so always read `non_compliant` next to `scored`.

**The ComplianceWorld to vCenter link.** The engine sums the world's
children, so each adapter instance makes its own vCenter object a child of
the Compliance World. Every cycle, after the instance resolves its
vCenter's `VMwareAdapter Instance`, it looks up the Compliance World and
adds the parent/child relationship through the Suite API. The add is
additive, so instances never remove each other's links. On a new install
the first cycle logs that the Compliance World was not found yet, and the
link is requested on the next cycle. The link is added each cycle and
never removed: a vCenter whose compliance adapter instance is deleted
stays a child of the Compliance World. Whether its last rollup values then
keep counting in the environment totals has not been observed yet.

All per-object and per-control detail lives on the foreign VMWARE
resources the adapter stitches to.

### Metrics scope

On every evaluated VMWARE object: the per-control
`Actual`/`Expected`/`Description` properties and `Compliant` metric
(1 / 0 / -1 not evaluated), plus `score`, `pass_count`, `fail_count`,
`total_count`, `unreadable_count`, `non_compliant`, `no_benchmark` and the
`profile_name` property. On each vCenter (`VMwareAdapter Instance`): the
per-vCenter rollup `VCF-CF Compliance|Rollup|<kind>|{scored,
non_compliant, no_benchmark, score_sum, avg_score}` for All, Host, VM,
vCenter, Cluster, vDS and Portgroup, plus objects per benchmark. On the
Compliance World: the engine-computed environment totals
`Rollup|Environment|{scored, non_compliant, no_benchmark, avg_score}` and
`Summary|last_scan_timestamp`. The full key list is in
[data-reference.md](data-reference.md).

## Dashboards

| Dashboard | What it is for |
|---|---|
| [VCF Content Factory] Compliance Environment Overview | The landing page: environment score, non-compliant objects and objects without a benchmark, compliance by vCenter and object type, objects per SCG version, the score trend, and open compliance alerts. |
| [VCF Content Factory] Compliance ESX Hosts | Pick a scope (vSphere World or one vCenter), see its hosts worst first with score and applied SCG, select a host to see its failing controls and their runbooks. |
| [VCF Content Factory] Compliance VMs | The same flow for VMs, built for thousands of objects (sorted list and totals, no heatmap). |
| [VCF Content Factory] Compliance vCenter & Networking | One page for the low-count kinds: vCenter, cluster, distributed switch and distributed portgroup lists, worst first, with the selected object's failing controls. |

The Environment Overview's four score tiles (Average Score, Non-Compliant
Objects, Objects Without Benchmark, Objects Scored) and its score trend
read the engine-computed `Rollup|Environment|*` metrics on the pack's own
Compliance World (build 86). **Nothing needs enabling in a policy**, and
no widget on any of the four dashboards needs policy changes. The Objects
Scored tile stays beside the others on purpose: with nothing scored, the
Non-Compliant Objects tile reads 0, and the Scored tile next to it shows
that the 0 has no denominator rather than meaning all clear. The totals
trail the per-vCenter views by one collection interval.

**Upgrading from a build that shipped super metrics (builds 61 to 85).**
Those builds bundled four super metrics on `VMWARE / vSphere World`
("[VCF Content Factory] Compliance Average Score", "... Non-Compliant
Objects", "... Objects Scored" and "... Objects Without Benchmark") that
had to be enabled in the vSphere World policy. Build 86 no longer ships or
uses them. The pak upgrade removes them from the instance, so there is
nothing to clean up by hand, and the Environment Overview that read them
is re-imported by the same upgrade and reads ComplianceWorld instead.

## Cross-Adapter Behavior

This pack is an **ARIA_OPS-style metric pusher**, not a standalone object
tree. It resolves the real VMWARE resources that the platform's vCenter
adapter already discovered and pushes compliance properties and stats onto
them via the Suite API:

- **VMWARE HostSystem, VirtualMachine, ClusterComputeResource,
  VmwareDistributedVirtualSwitch, DistributedVirtualPortgroup**: per-control
  results and per-object aggregates. vim25-backed objects resolve by MOID,
  scoped to the owning vCenter's instance UUID.
- **VMWARE vCenter (VMwareAdapter Instance)**: vCenter-appliance controls
  and the per-vCenter rollup. Resolved by `VCURL` (vCenter FQDN) and
  `VMEntityVCID` (vCenter Instance UUID), since that object is not
  vim25-backed and has no MOID. Each cycle the instance also makes its
  vCenter object a child of the pack's Compliance World (an additive
  Suite API relationship add, never removed), so the engine can sum the
  environment totals across vCenters.

Transport is the **ambient Suite API** — the adapter pushes onto the local
VCF Operations instance using the collector's ambient credentials; no Suite
API host/credential fields are configured. If the Suite API is unavailable
on a collector, the affected stitch is skipped for that cycle and
collection continues; compliance is never failed over a stitch error.

## Notable Behaviors

- **Unreadable counts as failing, and the adapter says so.** (Build 63,
  owner decision.) A setting the adapter could not read (connectivity,
  permissions, or a read method not supported on this version) counts
  against the object's score like a failure:
  score = pass / (pass + fail + unreadable). A disconnected host, where
  every setting is unreadable, scores 0. An unreadable setting is not a
  control violation: `fail_count` excludes it, its `Compliant` is -1 so no
  per-control alert fires, and `unreadable_count` counts it separately.
  The object raises "Compliance data not collected (<kind>)" (severity
  Immediate), whose recommendation says what to check. On a disconnected
  or version-unreadable host both that alert and the Critical "Host
  Compliance Score Degraded" alert (its score is 0) are expected, and both
  clear once the host reconnects and is read again. When
  nothing at all could be read (every attempted setting unreadable, or the
  object's version unreadable with no previous SCG), the object also has
  `collection_failed` = 1 (0 otherwise, pushed every cycle); the alert
  fires on either signal. `score`
  is not pushed only when nothing was attempted (no benchmark, non-vSAN
  cluster); VCF Ops then keeps its last value, so read `score` with
  `total_count`, `unreadable_count` and `no_benchmark`. The counters are
  pushed every cycle, with one exception: when the version that
  governs the object's SCG cannot be read (and there is no previous SCG to
  fall back on), `unreadable_count` is NOT pushed, because the adapter does
  not know which SCG's controls apply; its last value stays.
  `non_compliant` = 1 in that case.

- **A finding survives one unreadable cycle (build 86).** The per-control
  alerts and the Host Compliance Score Degraded alert (and their symptoms)
  cancel only after 3 consecutive collection cycles without the condition
  (wait stays 1 cycle). An unreadable control pushes `Compliant` = -1, not
  0, so before build 86 a single cycle where a failing control could not
  be read (a slow host, an esxcli timeout) cancelled its alert and the next
  good cycle raised a new one. The cost: a control you have fixed clears
  its alert after 3 cycles (15 minutes at the default 5 minute interval)
  instead of 1. The "Compliance data not collected" alerts keep a 1 cycle
  cancel: they describe the cycle that could not be read and clear on the
  first one that is. For Host Compliance Score Degraded the same setting
  works the other way: unreadable controls count as failing, so one
  unreadable cycle (one esxcli timeout can make up to 19 SCG 8.0 host
  controls unreadable) can lower a healthy host's score enough to raise it,
  and cancel 3 then holds it open for up to three cycles (15 minutes at
  the 5 minute interval). That is the safe direction; the "Compliance data
  not collected" alert raised in the same cycle says the cause was a read
  failure, not a setting change.

- **Per-vCenter averages when nothing was scored.** `Rollup|<K>|avg_score`
  is pushed only when `Rollup|<K>|scored` > 0; `scored` itself is pushed
  every cycle, 0 when nothing of that kind was scored. An `avg_score` next
  to `scored` = 0 is therefore a retained value from an earlier cycle, and
  the Overview view shows `non_compliant` / `scored` beside each average so
  that is visible at a glance.
- **A failed inventory listing holds back that vCenter's rollup for the
  kind (build 78).** If vCenter fails to list the VMs, distributed
  switches, portgroups or clusters in a cycle, the adapter does not push
  that kind's `Rollup|<K>|*` keys, nor the cross-kind `Rollup|All|*` and
  `Rollup|Benchmark|*|objects` keys, for that vCenter that cycle. The
  previous values stay, so the environment totals do not suddenly lose,
  for example, every VM of one vCenter. So a listing that keeps failing
  cannot freeze the rollup unnoticed, the vCenter object also carries
  `VCF-CF Compliance|Rollup|incomplete` (build 79), pushed every cycle: 1
  while keys are being held back, 0 once a complete cycle pushes
  everything. At 1 the vCenter's "Compliance data not collected (vCenter)"
  alert fires. To see which listing failed, look in the adapter log for
  "Inventory listing failed this cycle for" and the "Failed to enumerate"
  warning just before it; then check the collection account's inventory
  read permissions on that vCenter.

- **Version unreadable is not "no benchmark".** If the adapter cannot read
  the version that governs an object's SCG, it scores the object against
  the SCG it had last cycle. With no previous SCG (for example right after
  a collector restart), nothing was collected: the object scores 0, is
  non-compliant, has `collection_failed` = 1 (which raises "Compliance
  data not collected"), and is counted with its 0 in the rollup's `unknown`
  benchmark bucket. Only a version the adapter read, with no
  bundled SCG, is "no benchmark".

- **Unreadable objects are non-compliant and in the averages.** An object
  with any unreadable control has `non_compliant` = 1 and its real score
  (0 when nothing was read) in its vCenter's rollup averages. The pre-63
  "last-known score" carry-forward for unreadable hosts and the
  `Rollup|Host|scored_stale` key are retired.

- **Stale per-control results clean themselves up, every cycle.** VCF Ops
  keeps a metric's last value, so a control that failed (`Compliant` = 0)
  under an object's previous SCG would keep its alert open after the
  object moves to an SCG that does not evaluate that control (a host
  upgraded from 8.0 to 9.0, an instance switched from a fixed profile to
  Auto). At the end of every cycle the adapter reads the latest `Compliant`
  values of the controls outside each object's current SCG from VCF Ops
  (bulk `stats/latest` requests packed up to a URL-length limit: about 41
  requests for 5,000 VMs, 7 for 500 hosts on SCG 9.1), and sets only the ones
  still at 0 to -1 with an explanatory `Actual`, which cancels their
  alerts. It never creates a key the object did not have and does not
  touch a key already at -1 or 1, so after the first cleanup there is
  nothing more to push. Since build 76 the same read-back also covers
  controls that ARE in the object's SCG but were not evaluated this cycle
  because they do not apply (for example vSAN controls on a cluster where
  vSAN is not enabled): any 0 or 1 left on them is set to -1, so an old
  pass or an old failure cannot linger on a control that no longer
  applies. If that read fails, the object is skipped for the
  cycle (logged) and retried next cycle. Every cycle the adapter log
  carries one "Stale-control cleanup read" line with the objects queried,
  requests made, Compliant values returned and zeros cleaned, so a read
  that silently returns nothing can be told apart from "nothing stale". Objects whose version could not
  be read are not cleaned.

- **Strict TLS to vCenter by default.** Since build 50 the adapter
  validates the vCenter certificate against the platform trust store by
  default; `allowInsecure=true` is the explicit opt-out (see
  `installing.md`).

- **Fresh-instance discovery works on VCF Ops 9.0.2.** The adapter
  enumerates its synthetic world on the collect path
  (`discoverOnCollect()`), so a freshly created instance populates on its
  first collection cycle rather than waiting on a discovery task the
  platform may never invoke.

## Known Limitations

- **Prose expected values are manual review.** Controls whose SCG
  expected value is site-specific text (login banners, log server) are
  listed in `profiles/manual_review.csv` and never scored.
- **vCenter appliance settings are opt-in (build 74).** The adapter
  instance setting "Read vCenter appliance settings" (default off) decides
  whether the appliance (VAMI) controls are read. Off, they are manual
  review. On, the collection account needs the vsphere.local SSO group
  `SystemConfiguration.Administrators`, which also grants appliance write
  access.
- **vSAN controls only on vSAN clusters (build 74).** A cluster is scored
  on vSAN controls only when vSAN is enabled on it; before build 74 every
  cluster was.
- **Standard-switch controls are not scored (build 70).** The SCG's
  standard-switch security policy controls (reject forged transmits, MAC
  address changes and promiscuous mode on host vSwitches) belong to each
  ESX host's standard switches. Builds 57 to 69 read them from the
  distributed switch instead, which could report a pass while the hosts'
  standard switches stayed insecure. They are now manual review in every
  profile until a host-side standard-switch reader exists. The equivalent
  distributed-switch controls (`dvpg.network-reject-*-dvportgroup`) are
  still scored.
- **No remediation.** The pack reports compliance; it does not remediate
  (remediation is a planned future phase).
- Some controls requiring data channels the adapter cannot reach on a given
  target are classified as unaudited rather than scored — see
  `profiles/UNAUDITED_CONTROLS.md` in the pack source.
