# Overview — VCF Content Factory Compliance

## Stitched onto VMWARE resources (start here)

Almost everything this pack produces lives on objects the VMWARE (vSphere)
adapter already owns, not on the pack's own object. The generated
inventory tree shows only the pack's own `ComplianceWorld`, so use this
list to find the data:

| VMWARE object | What the pack pushes onto it |
|---|---|
| HostSystem, VirtualMachine, VMwareAdapter Instance (vCenter), ClusterComputeResource, VmwareDistributedVirtualSwitch, DistributedVirtualPortgroup | Per control: `VCF-CF Compliance\|<control_id>\|{Actual, Expected, Description}` (properties) and `...\|Compliant` (1 / 0 / -1 not evaluated; build 95: a control that could not be read is not pushed). Per object: `profile_name`, `score`, `pass_count`, `fail_count`, `total_count`, `unreadable_count`, `non_compliant`, `no_benchmark`, `collection_failed` (1 when nothing could be read on the object), and (build 95) `has_unreadable`, `unreadable_reason`, `unreadable_controls`, `object_kind`. |
| VMwareAdapter Instance (vCenter) | Per-vCenter rollup: `VCF-CF Compliance\|Rollup\|<All, Host, VM, vCenter, Cluster, vDS, Portgroup>\|{scored, non_compliant, no_benchmark, score_sum, avg_score, controls_evaluated, controls_passed, pass_rate}` (the last three build 95), `Rollup\|<kind>\|unmatched` per kind (build 88), `Rollup\|VM\|skipped_pods` (build 88), `Rollup\|incomplete`, and `Rollup\|Benchmark\|<SCG_6.7 ... SCG_9.1, none, unknown>\|objects`. |
| The same six kinds | 143 alert definitions, all type Compliance (subType 21): 136 per-control alerts, one per scored SCG control, named `VCF Content Factory Compliance Alert: <control_id>: <title>`, raised when that control's `Compliant` is 0, each with the SCG remediation as its recommendation; 6 "VCF Content Factory Compliance Alert: Compliance data not collected (<kind>)" alerts, one per kind, severity Immediate, raised when `has_unreadable` = 1 for two cycles in a row (build 95; on the vCenter also `Rollup\|incomplete` = 1), with a recommendation on what unreadable means and what to check; and 1 "VCF Content Factory Compliance Alert: Host Compliance Score Degraded" alert on HostSystem (score below 95 / 80). Every alert name starts with that prefix (build 86), so all of the pack's alerts sort and filter together. |

The full key list, with when each key is pushed, is in
[data-reference.md](data-reference.md) under "Keys pushed onto VMWARE resources".

The pack's own `ComplianceWorld` carries the environment totals,
`Rollup|Environment|{scored, non_compliant, no_benchmark, avg_score,
controls_evaluated, controls_passed, pass_rate}`
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
bundled SCG is reported as "no benchmark" and not scored. Since build 93
that is the only mode: the Compliance Profile setting is removed. Since
build 90 an overrides file in the VCF Operations configuration-file store
can turn controls off, replace expected values and pin the SCG version
for the whole instance or per object kind (see [overrides.md](overrides.md)).

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
  average of per-vCenter averages. Build 95 adds `controls_evaluated`,
  `controls_passed` (sums) and `pass_rate`, the
  summed `controls_passed` over the summed `controls_evaluated` times
  100: the percentage the dashboards show. This is how VMWARE fills
  vSphere World's own summary counts.

**Why the percentage is controls passing (build 95).** An average of
object scores weighs every object the same, so a port group with 7
evaluated controls (SCG 9.1) counted as much as a host with 56, and 58 port groups at about
93% and 103 VMs at about 74% lifted prod's environment to 79.9% while
vCenters scored 50 and vDS 75. The pass rate counts every evaluated
control once: controls passed over controls evaluated, per kind, per
vCenter and for the environment. Two numbers now answer two questions:
the pass rate says how much of the guide is met; the object counts
(`scored`, `non_compliant`) say how many objects have work to do.
Both come from what was read this cycle: unreadable controls are neither
passes nor in the denominator, and an object's own `score` follows the
same rule (build 95). Missing data is shown per object instead (see
"Unreadable data is skipped and flagged" below): there is no unreadable
rollup key. With nothing evaluated, no pass rate is pushed, never 100; the
cell keeps its last value and the Objects with Unreadable Controls list
says why. `avg_score` is still pushed but no dashboard shows it.

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
(1 / 0 / -1 not evaluated; an unreadable control is not pushed), plus
`score`, `pass_count`, `fail_count`, `total_count`, `unreadable_count`,
`non_compliant`, `no_benchmark`, `collection_failed`, `has_unreadable` and
the `profile_name`, `unreadable_reason`, `unreadable_controls` and
`object_kind` properties. On each vCenter (`VMwareAdapter Instance`): the
per-vCenter rollup `VCF-CF Compliance|Rollup|<kind>|{scored,
non_compliant, no_benchmark, score_sum, avg_score, controls_evaluated,
controls_passed, pass_rate}` for All, Host, VM,
vCenter, Cluster, vDS and Portgroup, plus objects per benchmark. On the
Compliance World: the engine-computed environment totals
`Rollup|Environment|{scored, non_compliant, no_benchmark, avg_score,
controls_evaluated, controls_passed, pass_rate}` and
`Summary|last_scan_timestamp`. The full key list is in
[data-reference.md](data-reference.md).

## Dashboards

| Dashboard | What it is for |
|---|---|
| [VCF Content Factory] Compliance Environment Overview | The landing page: environment controls passing, beside it the objects with unreadable controls (build 95), non-compliant objects and objects without a benchmark, compliance by vCenter and object type, objects per SCG version, the score trend, and open compliance alerts. |
| [VCF Content Factory] Compliance ESX Hosts | Pick a scope (vSphere World or one vCenter), see its hosts worst first with score and applied SCG, select a host to see its failing controls and their runbooks. The Host Score Heatmap colors by score alone, so a host that could not be read keeps its last color; Not Read in the host list and the host details marks it (build 95). |
| [VCF Content Factory] Compliance VMs | The same flow for VMs, built for thousands of objects (sorted list and totals, no heatmap). |
| [VCF Content Factory] Compliance vCenter & Networking | One page for the low-count kinds: vCenter, cluster, distributed switch and distributed portgroup lists, worst first, with the selected object's failing controls. |
| [VCF Content Factory] Compliance World Summary | Not in the dashboard menu: it is the **Summary tab** of the pack's Compliance World object (build 88, binds on 9.0.x from build 89; find Compliance World in the inventory and open it). The Environment Overview re-cut for that tab: the four environment tiles, the objects with unreadable controls, the last scan time, compliance by vCenter and object type, the score trend, objects per SCG version, and the open compliance alerts of the vCenter selected in the table. |

The pack's dashboards use no Section (header) widgets while VCF Operations
9.0.x is a supported target: the 9.0.x dashboard importer has no Section
widget type and rejects the whole dashboard, which is why build 88's
Summary tab did not appear on 9.0.x until build 89 removed its header row.

The alert panels (Open Compliance Alerts, Fleet Compliance Alerts and the
"Failing Controls on Selected ..." panels) filter on the alert type only,
so they list every pack alert of the Compliance type on the selected
object and its children: the per-control alerts, the "Compliance data not
collected" alerts and the Host Compliance Score Degraded alert alike. The
widget has no filter that separates them, and pinning all 143 alert
definitions per widget was ruled out. One exception after an upgrade: a
Host Compliance Score Degraded alert raised before build 57 can keep
subType 20 until it cancels and is not listed (seen on the devel lab, the
alerts listed only under `15_20`:
[#64, comment of 2026-10-28](https://github.com/sentania-labs/vcf-content-factory-sdk-compliance/issues/64#issuecomment-6461812901); see
[installing.md](installing.md#upgrading)).

On the Environment Overview nothing is selected when the page opens
(build 97, factory #177), so Open Compliance Alerts lists every
Compliance-type alert in the environment, not those of one object. Click
a vCenter in Compliance by vCenter and Object Type and the list narrows
to that vCenter and the objects under it. Before build 97 the first
vCenter row was selected on load, so the list opened already narrowed to
that vCenter.

The Environment Overview's four tiles (Controls Passing, Non-Compliant
Objects, Objects Without Benchmark, Objects Scored) and its score trend
read the engine-computed `Rollup|Environment|*` metrics on the pack's own
Compliance World (build 86). **Nothing needs enabling in a policy**, and
no widget on any of the four dashboards or the Compliance World Summary
tab needs policy changes. The Objects
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

- **Unreadable data is skipped and flagged per object.** (Build 95, Scott
  2026-10-14: "if we have missing data we just don't log it - but flag
  the stale metric, and then that becomes an alarm.") A setting the
  adapter could not read (connectivity, permissions, or a read method not
  supported on this version) is not pushed: no `Compliant` value, no
  Actual, for every cause, a host vCenter reports not responding included.
  Its last value and any per-control alert stay as they were. It is never
  a pass or a failure: the object's score is passed over evaluated over
  what was read, `non_compliant` is a failing control that was read, and
  the rollups and pass rates count only what was read. Instead the object
  carries `has_unreadable` = 1 (0 when everything was read, pushed every
  cycle), `unreadable_count`, `unreadable_reason` (the cause in plain
  words, for example "host not responding", "esxcli unavailable",
  "permission refused" or "appliance session refused", plus the detail the
  adapter logged) and `unreadable_controls` (the ids, the first 20 then
  "(+N more)"). An object with nothing readable this cycle (every attempted
  setting unreadable, or its version unreadable with no previous SCG)
  pushes only those signals and `collection_failed` = 1: no score, no
  counters, no `non_compliant`, so its last values stay on screen, not
  current; the Not Read column (`has_unreadable`) beside the score in
  the six per-kind views, and the same row in the ESX Hosts host details,
  mark them. A version-unreadable object gets no
  `unreadable_count` (its controls are not known). The flag drives the
  Objects with Unreadable Controls list beside the Controls Passing tile
  and the "Compliance data not collected (<kind>)" alert (severity
  Immediate), which fires after two cycles in a row and clears after one
  clean cycle. Builds 63 to 94 counted an unreadable setting as failing
  (pass / (pass + fail + unreadable)), pushed it as -1, made the object
  non-compliant and scored a disconnected host 0, which also raised Host
  Compliance Score Degraded. A whole-object outage no longer moves the
  score; a partial one scores what was read and can move it either way
  (hiding a passing control lowers it, hiding a failing one raises it).

- **A finding survives one unreadable cycle (build 86).** The per-control
  alerts and the Host Compliance Score Degraded alert (and their symptoms)
  cancel only after 3 consecutive collection cycles without the condition
  (wait stays 1 cycle). Builds 57 to 94 pushed `Compliant` = -1 for an
  unreadable control, so before build 86 a single cycle where a failing
  control could not be read (a slow host, an esxcli timeout) cancelled its
  alert and the next good cycle raised a new one; since build 95 an
  unreadable control is not pushed at all, so its alert simply stays. The
  cost: a control you have fixed clears its alert after 3 cycles (15
  minutes at the default 5 minute interval) instead of 1. The "Compliance
  data not collected" alerts wait 2 cycles and cancel after 1 (build 95):
  one slow cycle does not raise them, and they clear on the first cycle
  that reads everything. Since build 95 a host with nothing readable gets
  no score, so it no longer raises Host Compliance Score Degraded; a host
  read in part is scored over what was read, which can move its score
  either way and so can raise or cancel Score Degraded.

- **Only objects with a VCF Ops resource are counted (build 88).** The
  per-vCenter rollup, and so the environment totals, count only objects
  the adapter found a VMWARE resource for. Before build 88 an object
  vCenter listed but VCF Ops did not have was still scored and counted,
  so the totals could include objects no dashboard could show (on the
  devel lab, 18 Supervisor Pods made wld01 report 43 scored VMs against
  25 VirtualMachine objects). Now such an object is not read or scored;
  it is counted in `VCF-CF Compliance|Rollup|<kind>|unmatched` on the
  vCenter object (pushed with the kind's other keys, 0 when none), and
  the adapter log names them once per cycle per kind at INFO, in a line
  that starts `<Kind>: N object(s) with no matching VCF Ops resource`
  (first 20 by name and MOID). The per-object "no match" line moved from
  WARN to DEBUG. If VCF Ops' own resource list for a kind cannot be read
  in a cycle, that kind is not scored and its keys are held back with
  `Rollup|incomplete` = 1, exactly like a failed vCenter listing, rather
  than every object being reported as unmatched.
- **Matched on MOID and vCenter only (build 102, issue #20).** An object
  matches the VMWARE resource with the same MOID (`VMEntityObjectID`)
  and this account's vCenter instance UUID (`VMEntityVCID`), the identity
  the Broadcom vSphere packs use. There is no name match any more: the
  old exact-name and FQDN / short-name fallbacks could pick a different
  object that shared a name prefix, and the pick could change from cycle
  to cycle. A VCF Ops resource row with no UUID, no MOID or no vCenter
  UUID is not used, and two rows with the same MOID in this vCenter match
  neither; the adapter counts those rows and names the first once per
  cycle per kind at INFO (`<kind>: N row(s) not indexed`). The objects
  they would have matched are counted unmatched. If the vCenter instance
  UUID cannot be read in a cycle, hosts, VMs, clusters, switches and
  port groups are held back with `Rollup|incomplete` = 1 instead of
  matched on a bare MOID. A kind is held back the same way when its list
  has rows but none of this vCenter and at least one with no vCenter
  UUID, since this vCenter's objects may be among those rows; the
  stitcher logs a WARN (`<kind> not matched: N of M row(s) carry no
  VMEntityVCID`) instead of the kind's counts dropping to 0. Every load
  line records how many rows carry the vCenter UUID (`... ; N of M row(s)
  carry VMEntityVCID`), for each of the five kinds.
- **vSphere Pods are skipped (build 88).** VMs whose guest id starts with
  `crx` (vSphere Pods, which VCF Ops lists as kind Pod) are out of scope:
  not scored, not unmatched, counted in
  `VCF-CF Compliance|Rollup|VM|skipped_pods` and named at DEBUG. The guest
  id is read in the same bulk call that lists the VMs. Only the `crx`
  prefix is matched: no vendor list of every CRX guest id was found, and
  devel Pods show guest "VMware CRX Pod 1 (64-bit)" (`crxPod1Guest`).

- **No pass rate when nothing was evaluated (build 95).**
  `Rollup|<K>|pass_rate` is pushed only when `Rollup|<K>|controls_evaluated`
  > 0; the two control counts are pushed every cycle (held back with the
  kind when its listing fails). A kind whose every control was unreadable
  shows `controls_evaluated` 0 and no new rate, so the table cell keeps
  the last rate it had (never 100 for nothing). The objects behind it are
  on the Objects with Unreadable Controls list with their reason, and
  their "Compliance data not collected" alert fires after two cycles.
- **Per-vCenter averages when nothing was scored.** `Rollup|<K>|avg_score`
  is pushed only when `Rollup|<K>|scored` > 0; `scored` itself is pushed
  every cycle, 0 when nothing of that kind was scored. An `avg_score` next
  to `scored` = 0 is therefore a retained value from an earlier cycle, and
  the Overview view shows `non_compliant` / `scored` beside each average so
  that is visible at a glance.
- **A failed inventory listing holds back that vCenter's rollup for the
  kind (build 78).** If vCenter fails to list the hosts (build 95,
  issue #18; before, a failed host listing failed the whole cycle with no
  signal), VMs, distributed switches, portgroups or clusters in a cycle, the adapter does not push
  that kind's `Rollup|<K>|*` keys, nor the cross-kind `Rollup|All|*`,
  `Rollup|Benchmark|*|objects` and (build 102) `Rollup|Benchmark|*|scored_objects`
  keys, for that vCenter that cycle. The
  previous values stay, so the environment totals do not suddenly lose,
  for example, every VM of one vCenter. So a listing that keeps failing
  cannot freeze the rollup unnoticed, the vCenter object also carries
  `VCF-CF Compliance|Rollup|incomplete` (build 79), pushed every cycle: 1
  while keys are being held back, 0 once a complete cycle pushes
  everything. At 1 the vCenter's "Compliance data not collected (vCenter)"
  alert fires. To see which listing failed, look in the adapter log for
  "Inventory listing failed this cycle for" and the "Failed to enumerate"
  warning just before it; then check the collection account's inventory
  read permissions on that vCenter. Since build 93 a cycle that cannot
  reach vCenter at all (connection, login or certificate failure) also
  pushes `Rollup|incomplete` = 1 on the vCenter object, and nothing
  else, before the cycle fails; the adapter log says "not reached this
  cycle". The vCenter object is found without vCenter only by the id an
  earlier cycle since the last account edit resolved, or by a VCURL
  equal to the entered host.

- **Version unreadable is not "no benchmark".** If the adapter cannot read
  the version that governs an object's SCG, it scores the object against
  the SCG it had last cycle. With no previous SCG (for example right after
  a collector restart), nothing was collected: build 95 pushes only
  `has_unreadable` = 1, `collection_failed` = 1 and the reason ("product
  version unreadable"), which raises "Compliance data not collected" after
  two cycles; the object is counted only in the rollup's `unknown`
  benchmark bucket (not scored, not non-compliant). Only a version the
  adapter read, with no bundled SCG, is "no benchmark".

- **Unreadable objects count by what was read (build 95).** An object
  with some unreadable controls is scored over the controls that were
  read and is non-compliant only for a failing control that was read; an
  object with nothing read is not scored and not counted as
  non-compliant. Both are flagged (`has_unreadable` = 1). Builds 63 to 94
  made every such object non-compliant and averaged a nothing-read object
  in at 0. The pre-63 "last-known score" carry-forward for unreadable
  hosts and the `Rollup|Host|scored_stale` key stay retired.

- **What a cycle costs is in the log (build 95, issue #17).** The
  "ComplianceAdapter collection complete" INFO line ends with
  `timing: ...`: wall time, SOAP calls and Suite API calls for inventory,
  host reads, VM reads, network reads (switches, portgroups, clusters),
  vCenter reads, esxcli, pushes, the bulk shadow and everything else, then
  the cycle totals. Time is counted once: a push made inside the host loop
  counts as pushes, not host reads. The same build cuts calls without
  changing results: one session keepalive per cycle instead of one per
  read, inventory names taken from the listing call, connections kept
  open between calls, and a property path that does not resolve never
  falls back to fetching a host's or VM's whole configuration (those
  controls are unreadable with reason `prefix-cap`). When vCenter drops
  the session mid-cycle the adapter logs in again once; if that login
  fails (a changed password, for example) it does not try again until the
  next cycle, so a bad credential costs one failed login per cycle, not
  one per read, and cannot trip the SSO lockout policy. The reads after it
  are unreadable. Editing the account while a cycle runs does not switch
  that cycle to the new settings part-way: it finishes on the clients it
  started with. The edit closes its vCenter connection, so its remaining
  vCenter inventory reads are unreadable (never read from another
  vCenter); its appliance reads, if any, still go to the old vCenter,
  its own object. The next cycle uses the new settings and starts fresh:
  nothing the interrupted cycle recorded (the benchmark each object was
  scored against, the vCenter object it resolved) carries over, so the
  next cycle never scores the new vCenter against the old one's
  benchmark or flags "not collected" on the old vCenter.

- **Batched Suite API pushes (build 104, issue #17).** Every value a
  cycle pushes onto VMWARE resources (each object's properties and stats,
  the cleanup's -1 keys, the vCenter rollup and overrides status) is
  queued and sent with the buildkit 1.0.24 batch pushes, stats first, then
  properties, in requests of at most 100 resources and about 1 MB each.
  The queue is sent inside the walk whenever it reaches 500 resource
  entries or about 16 MB, so it stays bounded and its time counts against
  the cycle budget, and the rest at the end of the cycle. Same resources,
  keys and values as the per-object pushes of build 103 (two calls per
  object); every value of a cycle carries one timestamp, the cycle's
  start. Stats go first because they carry every alerting signal (scores,
  `has_unreadable`, each `|Compliant`, `Rollup|incomplete`), so a failed
  properties request never leaves those stale. One log line per cycle
  says what went out (`Suite API push: ...`, INFO), or `Suite API push
  NOT clean: ...` (WARN) with the counts and the reason when a request
  failed, was refused or the call stopped: the values not delivered keep
  their last value until the next cycle, and scoring is never affected.
  Stop Collecting is checked before each request; after a stop nothing
  more is sent and what was still queued is dropped (one WARN), as build
  103 pushed nothing after a stop. A cycle that cannot reach vCenter
  sends `Rollup|incomplete` = 1 at once. A 2xx means accepted, not landed
  (VCF Operations drops an id that matches no resource without an
  error): the per-cycle resource lists keep the ids current, and the
  not-reached marker checks the vCenter object id it remembered against
  the current VMwareAdapter Instance list first (a replaced object is
  resolved again by the entered host).

- **Each kind is read in bulk (build 103, issue #17).** Hosts, VMs,
  distributed switches, portgroups and clusters are each read with one
  `RetrieveProperties` per page of objects (hosts 10, VMs and clusters
  50, switches and portgroups 100), asking for every property any
  benchmark the kind can be scored against needs (the paths come from
  the benchmarks' read recipes, plus a host's version and connection
  state and a cluster's vSAN configuration). The controls are then
  evaluated from that data with the same readers as before. A host's
  advanced settings come from its `config.option` in the page instead of
  a `QueryOptions` call to the host. The two returned identical maps on
  the 10 hosts compared before the switch: three devel vCenters (9.1.1),
  ESXi 9.1.1 (builds 25714478 and 25782009), read with an account that
  has the Administrator role. Older ESXi versions and a Read-only role
  were not compared; a key `config.option` leaves out would score
  "(undefined)", a FAIL, never a pass. Pages follow the walk's order,
  so the time limit, the resume point and the cuts below work as before.
  Fallback, per object: when a page's call fails (a fault, the response
  size cap, an object deleted meanwhile) its objects are read one at a
  time as in build 102, with one WARN per kind (a page over the response
  size cap also sends the rest of that kind one at a time for the cycle,
  instead of fetching each page up to the cap); when a value is not in an
  object's row (unset, faulted or a rejected path) that control is read
  one at a time, so its value, or UNREADABLE with the per-object reason,
  is what build 102 would have produced; a missing value is never a pass.
  esxcli and the vCenter object's own reads stay per object. One INFO
  line per kind, `Bulk read <kind>: ...`, gives the objects, calls, paths,
  bytes and what was read one at a time. Measured on devel (three
  vCenters, 2 to 6 hosts and 25 to 45 VMs each): about 520 to 710 vCenter
  calls per cycle before, 34 to 62 after, nearly all of the rest esxcli.

- **Stop Collecting stops within one object (build 95, issue #16).**
  Stopping collection on the account abandons the running cycle before the
  next host, VM, switch, portgroup or cluster, instead of after the whole
  vCenter walk. Nothing more is read or pushed that cycle (values already
  pushed stay), and one WARN says where it stopped ("ComplianceAdapter
  cycle abandoned after ...") followed by the cycle's timing so far.

- **A cycle has a time limit and a timeout breaker (build 96, issue
  #16).** A cycle may take about 95% of the account's collection
  interval (285 s at the default 5 minutes; the adapter reads the
  interval from the platform, else the Compliance World resource, else
  uses 5 minutes, clamps it to 60 s to 24 h, and logs one "Cycle limits:"
  INFO line saying which). The limit is checked before each call and
  does not cut a call in flight, so the worst case is the budget plus one
  call (30 s connect plus 120 s read): 435 s on a 5 minute interval.
  Build 103: esxcli calls take the same read timeout as every other
  vCenter call (they had their own fixed 120 s, the same value). A
  walk that took up to 95% of the interval completed in build 95 and
  still does; a longer one ends early every cycle and keeps the alert
  raised, and the remedy is a longer collection interval. A
  cycle also ends after 5 vCenter calls in a row time out with no answer
  between them (a vCenter that accepts connections but does not answer);
  the appliance (VAMI) and esxcli calls count too.
  - **Order.** The kinds run in a fixed round: the vCenter object,
    distributed switches, portgroups, clusters, hosts, VMs. A cycle that
    ended early is followed by one that starts in the kind it stopped
    in, carries on through the kinds after it, and wraps round to the
    ones before it, so no kind (VMs behind a long host walk, say) waits
    for good.
  - **When a limit is reached**, no more vCenter calls are made. The
    object being read is not pushed at all (no partial score: its last
    values stay, as for an object not visited), the kind being collected
    and every kind not yet started are held back (`Rollup|incomplete` =
    1, which raises "Compliance data not collected (vCenter)"; their
    Rollup keys keep their values), objects already pushed keep this
    cycle's values, the rollup is still pushed, and one WARN says where
    and why ("Cycle ended early ..."); the collection-complete line ends
    with "ENDED EARLY". The bulk shadow stops. The stale-key cleanup runs
    per kind, right after that kind's walk; when the budget stops it, the
    rest is carried: a cycle that resumes the kind runs it first (those
    objects lie before the resume point and are not visited again), and
    otherwise it runs after the kind's next walk, except for objects that
    walk visits again (their fresh entry replaces the carried one, so an
    old plan never sets -1 on a key that became live). A version read
    refused by the budget counts as a cut, not as "version unreadable".
    An object is cut only when a call was refused while it was read; one
    whose reads all finished before the deadline is pushed in full.
  - **Resume.** In the kind it stopped in, the next cycle reads only the
    objects after the last one finished; reaching the end of that kind
    finishes it for this pass and the walk goes on to the next kind. The
    kind's rollup is then pushed over every object of the kind (the part
    read by the earlier cycles of the pass is carried and added), so a
    cycle that finishes the round clears `Rollup|incomplete`; only a
    cycle that ends early again keeps the kind held back. Each kind is
    walked in MOID order. A pass over every object therefore spreads
    over consecutive cycles, and every object is read again within a
    bounded number of cycles: about the time a full walk takes divided by
    the budget, plus one.
  - **An object that never fits costs at most two cycles.** An object
    cut by the limit is retried first the next cycle; cut a second time
    in a row, only its markers are pushed (Not Read = 1 and the reason
    "cut by cycle budget twice", no score: its last values stay), the
    kind is held back, and the walk moves past it. The two cuts must be
    on consecutive cycles.
  - **A host that stops answering costs one timeout per visit.** When a
    host's advanced-settings read or an esxcli command (both relayed by
    vCenter to the host) times out, the rest of that host's host-relayed
    reads (advanced settings and esxcli) are skipped for the cycle
    (UNREADABLE, reason "host not answering"). Since build 103 a host's
    advanced settings normally come from the bulk read (vCenter's
    inventory), so the host-relayed call is usually its first esxcli
    command. Properties vCenter answers
    from its own inventory are still read, as in build 95, so the host is
    scored over what was read and flagged Not Read. The mark lasts one
    cycle, so the host costs one timeout each time the walk reaches it.
  - **If every cycle ends early** on a vCenter that answers normally, its
    walk is longer than the interval allows: lengthen the account's
    collection interval (docs/installing.md).
  - The cheap calls (the keepalive and single-value reads such as a
    name, a connection state or a version) wait 30 s for an answer, not
    120 s.

- **Bulk read shadow (build 95; reversed in build 103).** Build 95 to
  102 scored from the per-object reads and, after each kind, read it
  again in bulk and compared. Zero disagreements on devel (build 95's
  proxy log, then build 103's read-only comparison on all three devel
  vCenters: 3,380 outcomes, every kind) let build 103 score from the bulk
  read. The shadow now runs the other way: after each kind, the objects
  scored from the bulk read are read again one at a time (advanced
  settings and vim properties, not esxcli) and compared. Nothing it finds
  changes a score, a push or an alert. Each cycle logs one INFO line per
  kind, starting `Bulk shadow <kind>:`, with the controls compared and
  the disagreements, and one `Bulk shadow disagreement:` line per
  difference (object, control, bulk value, per-object value; the first
  25 per kind). It costs what a build 102 cycle cost, so it is skipped
  when the cycle's time budget is used up and stops if the budget runs
  out during it. Shadow mode runs only in a dev-preview build (version 0.0.0.N) and is
  off in a tagged release (1.0.0.N), decided each cycle from the build's
  own version stamp (`conf/version.txt` beside describe.xml; no file or an
  unreadable one is off). It is not a user setting. The decision is logged
  once at INFO: "Bulk shadow mode: dev-preview build 0.0.0.95: on" or
  "... release build 1.0.0.95: off".

- **Stale per-control results clean themselves up, every cycle.** VCF Ops
  keeps a metric's last value, so a control that failed (`Compliant` = 0)
  under an object's previous SCG would keep its alert open after the
  object moves to an SCG that does not evaluate that control (a host
  upgraded from 8.0 to 9.0, an instance moved from a fixed profile to
  Auto by the build 93 upgrade, a pin added or removed in the overrides
  file). At the end of every cycle the adapter reads the latest `Compliant`
  values of the controls outside each object's current SCG from VCF Ops
  (bulk `stats/latest` requests packed up to a URL-length limit: about 41
  requests for 5,000 VMs, 7 for 500 hosts on SCG 9.1), and sets only the ones
  still at 0 to -1 with an explanatory `Actual`, which cancels their
  alerts. It never creates a key the object did not have and leaves a
  lingering 1 outside the SCG alone. Since build 96 (issue #42) a key it
  finds already at -1 gets -1 again on later cycles while the control
  stays out of the object's SCG, up to 4 -1 pushes per key in all: a
  per-control alert cancels only after three fresh non-failing samples,
  and one -1 used to leave it open after a guide version change. The
  repeats ride the object's own per-cycle push, as a Skip does, so they
  are made whenever the object is visited, even on a cycle whose cleanup
  is cut; a cleanup cut by the cycle budget is carried to a later cycle
  (see the cycle limit above). A -1 counts only once the read-back
  (which asks for each key's last 5 samples) shows it landed, so a push
  that failed is made again. The count is kept in memory, so after a
  restart a retired key gets at most 4 more. Since build 76 the same read-back also covers
  controls that ARE in the object's SCG but were not evaluated this cycle
  because they do not apply (for example vSAN controls on a cluster where
  vSAN is not enabled): any 0 or 1 left on them is set to -1, so an old
  pass or an old failure cannot linger on a control that no longer
  applies. If that read fails, the object is skipped for the
  cycle (logged) and retried next cycle. Every cycle the adapter log
  carries one "Stale-control cleanup read" line with the objects queried,
  requests made, Compliant values returned, zeros cleaned and (build 96)
  retired keys pushed -1 again, so a read
  that silently returns nothing can be told apart from "nothing stale". Objects whose version could not
  be read are not cleaned.

- **Strict TLS to vCenter, always.** Since build 50 the adapter
  validates the vCenter certificate against the platform trust store.
  Since build 93 there is no opt-out (Allow Insecure SSL is removed);
  instead the adapter declares the vCenter endpoint to VCF Operations
  (the framework's `certificateCheckUrls` hook), so Validate Connection
  shows the Review and Accept Certificate dialog for an untrusted
  certificate, and the accepted certificate is stored on the instance
  and trusted on every cycle. The platform trust manager checks the
  chain only, so the adapter also checks the certificate name itself on
  every connection to vCenter (REST, appliance API, SOAP and esxcli,
  Test Connection included): vCenter must be entered by the name on its
  certificate (see `installing.md`).

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
