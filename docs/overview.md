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
| [VCF Content Factory] Compliance ESX Hosts | Pick a scope (vSphere World or one vCenter), see its hosts worst first with score and applied SCG, select a host to see its failing controls and their runbooks. |
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
definitions per widget was ruled out.

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
  current; the Not Fully Read column (`has_unreadable`) beside the score in
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
  are unreadable.

- **Stop Collecting stops within one object (build 95, issue #16).**
  Stopping collection on the account abandons the running cycle before the
  next host, VM, switch, portgroup or cluster, instead of after the whole
  vCenter walk. Nothing more is read or pushed that cycle (values already
  pushed stay), and one WARN says where it stopped ("ComplianceAdapter
  cycle abandoned after ...") followed by the cycle's timing so far.
  There is no time limit on a cycle yet.

- **Bulk read shadow (build 95).** After each kind is scored, the adapter
  also reads that kind's objects in a few paged bulk calls, evaluates the
  same controls from that data and compares. Nothing it finds changes a
  score, a push or an alert. Each cycle logs one INFO line per kind,
  starting `Bulk shadow <kind>:`, with the controls compared and the
  disagreements, the pages read and their size (total bytes and the
  largest page; each page's size is at DEBUG), and one
  `Bulk shadow disagreement:` line per difference (object, control,
  per-object value, bulk value; the first 25 per kind). VMs are read 50
  per page, hosts 10.
  Zero disagreements across every vCenter is what lets a later build
  score from the bulk reads, which grow with pages instead of objects.
  Shadow mode runs only in a dev-preview build (version 0.0.0.N) and is
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
