# Scoring, data keys and alerts

The detail behind the README: how an object's benchmark is chosen, how
it is scored, every key the pack pushes, and the alerts it raises. For
installation see [installing.md](installing.md); for how the pack works
inside see [overview.md](overview.md).

## Adapter instance settings

| Field | Required | Default | Description |
|---|---|---|---|
| vCenter Host / IP | Yes | - | vCenter, by the name on its certificate (installing.md, TLS section) |
| Username | Yes | - | vCenter SSO credentials |
| Password | Yes | - | vCenter SSO credentials |
| Overrides file | No | - | Advanced Settings. Build 90. Name of your copy of `compliance_overrides_template` in Infrastructure Operations > Configurations > Management Packs Configuration, without `.xml`. Empty: no overrides, no fetch. See [overrides.md](overrides.md) |
| Read vCenter appliance settings | No | false | Advanced Settings; a true/false choice. Read the vCenter appliance (VAMI) settings (SSH, NTP, syslog, TLS profile, root password expiry, FIPS). Off: those controls are reported for manual review. On: needs the collection account in the vsphere.local SSO group `SystemConfiguration.Administrators`, which also grants appliance write access (no read-only appliance role exists) |

**No profile setting (build 93).** The Compliance Profile setting is
removed and every instance runs Auto (by version), including one that
stored a fixed SCG (for example `VMware_SCG_9.1`), `Custom`, or nothing
(the pre-version-aware SCG 8.0 default). If the platform still hands
the adapter the stored value, it logs one INFO line each time it is
configured, naming that value; VCF Operations may drop it on upgrade,
so record it first (installing.md, Upgrading). To score every object of
an instance against one SCG, use the overrides file's instance-wide
pin, `<Profile version="SCG 9.1"/>`.

**No Allow Insecure SSL (build 93).** The vCenter certificate is always
validated, chain and name; an untrusted one is accepted in the Validate
Connection dialog. If the platform still hands the adapter a stored
`allowInsecure=true`, it logs one WARN each time it is configured. See
installing.md, TLS section and Upgrading.

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
  collected. Build 95: only the unreadable signals are pushed,
  `has_unreadable` = 1, `collection_failed` = 1 and `unreadable_reason` =
  `product version unreadable (...)` (no score, no counters, no
  `non_compliant`; the last values stay). It raises "Compliance data not
  collected" after two cycles.
- **Overrides file (build 90):** applied on top. A `Profile` pin
  replaces Auto for every kind (no `kind`, the instance-wide pin) or for
  one kind (a `kind` pin wins over the instance-wide pin), whatever the
  object's version; `Skip` removes
  a control from every loaded profile; `Override` replaces its expected
  value. The manual-review list still applies. See
  [overrides.md](overrides.md).

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
[building.md](building.md)). `profiles/manual_review.csv` lists controls that
are reported for manual review and never scored: those whose SCG expected
value is prose (site-specific text), and (build 70) the standard-switch
security controls, which live on each ESX host's vSwitches and were
wrongly read from the distributed switch. The file is required: a pak
without it fails to load rather than scoring those controls.

To tune controls for your site, use an overrides file
([overrides.md](overrides.md)).

## Keys pushed onto VMWARE resources

Per-control (on the object the control applies to):
```
VCF-CF Compliance|<control_id>|Actual        property
VCF-CF Compliance|<control_id>|Expected      property
VCF-CF Compliance|<control_id>|Description   property
VCF-CF Compliance|<control_id>|Compliant     metric: 1 compliant, 0 non-compliant,
                                             -1 not evaluated (no longer in the
                                             applied benchmark, or skipped by the
                                             overrides file)
```

Build 95 (Scott 2026-10-14): a control the adapter could not read this
cycle is not pushed at all, whatever the cause (a host vCenter reports
not responding included): no Compliant value, no Actual. Its last value,
and any alert on it, stay as they were; the object's `has_unreadable`
flag says the data is not current. Builds 57 to 94 pushed -1 and Actual
`(unreadable)`.

Build 90: for a control whose expected value comes from the overrides
file, Expected reads `<value> (site override)` and a read Actual reads
`<actual>, expected <value> (site override)`. A skipped control's
Actual reads `(skipped by override file <name>)` and its Compliant reads
-1, pushed every cycle while the Skip is in force (build 92).

Actual values you can see:

- the value read, for example `TRUE` or `900`.
- `(undefined)`: the setting is not set on the object (absent, or set
  with an empty value). Compliant is 1 when the guide allows it to be
  unset (`X or Undefined`, `X or Not Present`, bare `Not Present`) and 0
  otherwise (build 90; before build 90 an unset setting was skipped).
- `""`: the setting is set with an empty value and the guide's value is
  explicitly empty (`esx.network-dvfilter`); Compliant is 1.
- `<key>=<value>; <key>=<value>`: a control whose parameter is a key
  pattern (`vm.dvfilter`, `ethernet*.filter*.name`) lists every
  matching setting with its value, for example
  `ethernet0.filter0.name=dvfilter-generic-vmware`. Any match fails
  `Not Present` (build 90; before build 90 this control always passed).
- `(unreadable)`: no longer pushed (build 95); an Actual reading
  `(unreadable)` is left from build 94 or earlier and is replaced the
  next time the control is read.
- the site-override and skipped forms above.

Per object:
```
VCF-CF Compliance|profile_name       property: benchmark applied, or "no benchmark for ..."
VCF-CF Compliance|score              0-100%: pass / (pass + fail), over what was read
                                     (build 95; unreadable is in neither count); pushed only
                                     when at least one control was read
VCF-CF Compliance|pass_count         controls that passed
VCF-CF Compliance|fail_count         controls evaluated and failed (unreadable NOT included)
VCF-CF Compliance|total_count        pass + fail; not pushed when nothing was read (it
                                     keeps its last value; has_unreadable = 1 marks that)
VCF-CF Compliance|unreadable_count   controls not read this cycle; not pushed when the
                                     governing version cannot be read
VCF-CF Compliance|non_compliant      1 when fail_count > 0 (build 95: a failing control
                                     that was read; unreadable alone is not non-compliant)
VCF-CF Compliance|no_benchmark       1 when the version has no SCG
VCF-CF Compliance|collection_failed  1 when nothing could be read on the object (every attempted
                                     control unreadable, or its version unreadable with no
                                     previous SCG); 0 otherwise; pushed every cycle
VCF-CF Compliance|has_unreadable     build 95: 1 when any control could not be read this
                                     cycle, else 0; pushed every cycle on every object; the
                                     "Compliance data not collected" alerts fire on it
VCF-CF Compliance|unreadable_reason  build 95, property: why, per cause in plain words plus
                                     the detail the adapter logged (see below); "" when
                                     everything was read
VCF-CF Compliance|unreadable_controls build 95, property: the unreadable control ids,
                                     sorted, the first 20 then "(+N more)"; "" when none
VCF-CF Compliance|object_kind        build 95, property: ESX host, VM, vCenter, Cluster,
                                     Distributed switch or Distributed portgroup (the kind
                                     column of the Objects with Unreadable Controls list)
```

**An object with nothing readable** this cycle (every attempted control
unreadable, or its version unreadable with no previous SCG) pushes only
`has_unreadable` = 1, `unreadable_count` (when known), `collection_failed`
= 1, `unreadable_reason`, `unreadable_controls` and `object_kind`: no
score, no pass / fail / total, no `non_compliant`, no per-control value.
Its last score and `total_count` stay on screen, not current: the Not
Fully Read column (`has_unreadable`) beside the score in the six per-kind
views, and the same row in the ESX Hosts host details, mark them (the
ESX Hosts heatmap colors by score alone and does not). A
version-unreadable object's `unreadable_controls` reads `(not known: the
benchmark depends on the version)`: its controls are not invented.

**`unreadable_reason` wording** (build 95). Each cause the adapter logs
is given in plain words, followed by the logged detail in brackets, for
example `host not responding (host-not-connected:
connectionState=notResponding)`. With several causes, each is followed by
its control count and they are listed most controls first, separated by
"; ", at most 1000 characters (then "(+N more causes)"). The plain words
per logged reason code:

| Reason code | Plain words |
|---|---|
| `host-not-connected` (connectionState notResponding / disconnected) | host not responding / host disconnected |
| `advanced-settings-unreadable` (host flapped) | host disconnected during the read |
| `advanced-settings-unreadable` (other) | host advanced settings unreadable |
| `extraconfig-unreadable` | VM advanced settings unreadable |
| `vcenter-settings-unreadable` | vCenter advanced settings unreadable |
| `esxcli-host-unreachable` | host unreachable for esxcli |
| `esxcli-unavailable` | esxcli unavailable |
| `esxcli-command-failed` / `esxcli-field-missing` | esxcli command failed / esxcli field missing |
| `soap-fault` naming NoPermission | permission refused |
| `soap-fault` (other) | vCenter returned a fault |
| `response-too-large` | vCenter response over the size cap |
| `missing-element` | setting not returned by vCenter |
| `prefix-cap` | property path not reachable |
| `vami-session` | appliance session refused |
| `vami-http-401` / `vami-http-403` | appliance permission refused |
| `vami-http-<other>` | appliance returned HTTP `<status>` |
| `vami-exception` / `vami-parse` / `vami-field-missing` | appliance not reached / appliance answer not readable / appliance field missing |
| `vsan-probe-failed` | vSAN probe failed |
| `version-unreadable` | product version unreadable |
| any other code | could not be read (`<code>`) |


Per vCenter (on each VMWARE `VMwareAdapter Instance`), `<K>` in `All`,
`Host`, `VM`, `vCenter`, `Cluster`, `vDS`, `Portgroup`:
```
VCF-CF Compliance|Rollup|<K>|scored
VCF-CF Compliance|Rollup|<K>|non_compliant
VCF-CF Compliance|Rollup|<K>|no_benchmark
VCF-CF Compliance|Rollup|<K>|score_sum
VCF-CF Compliance|Rollup|<K>|avg_score        only when scored > 0; mean of the object scores
                                               (kept, no longer displayed, build 95)
VCF-CF Compliance|Rollup|<K>|controls_evaluated  build 95: controls passed plus failed, summed
                                               over the kind's scored objects
VCF-CF Compliance|Rollup|<K>|controls_passed     build 95: controls passed
VCF-CF Compliance|Rollup|<K>|pass_rate           build 95, %: controls_passed /
                                               controls_evaluated * 100; only when
                                               controls_evaluated > 0 (never 100 on nothing)
VCF-CF Compliance|Rollup|<K>|unmatched        not for All (build 88): objects vCenter listed
                                               with no matching VCF Ops resource, so not
                                               scored and in no other key; 0 when none
VCF-CF Compliance|Rollup|VM|skipped_pods      vSphere Pod VMs skipped (build 88); 0 when none
VCF-CF Compliance|Rollup|incomplete           0/1, every cycle: 1 when an inventory listing
                                               (vCenter's, or VCF Ops' resource list for a
                                               kind) failed and rollup keys were held back,
                                               or (build 93) the cycle could not reach
                                               vCenter at all (the only key pushed then)
VCF-CF Compliance|Rollup|Benchmark|<B>|objects B in SCG_6.7, SCG_7.0, SCG_8.0,
                                               SCG_9.0, SCG_9.1, none, unknown
```

Overrides file status, per vCenter (build 90), pushed every cycle:
```
VCF-CF Compliance|Summary|overrides_file        property: the instance's Overrides file setting ("" when none)
VCF-CF Compliance|Summary|overrides_status      property: none | OK | N rejected | absent |
                                                parse failed, last good from <time> |
                                                parse failed, no previous copy |
                                                fetch failed: <reason>, last good from <time> |
                                                fetch failed N cycles: <reason>, last good from <time> |
                                                fetch failed: <reason>, no copy in force
                                                (<time> is the collector's local time; <reason> is
                                                refused (HTTP 401|403) | HTTP <status> |
                                                no Suite API channel | no answer (<error>))
VCF-CF Compliance|Summary|overrides_skipped     Skip entries in force for the instance's guide
                                                versions (its mode's, or the pinned one per kind)
VCF-CF Compliance|Summary|overrides_overridden  Override entries in force, counted the same way
VCF-CF Compliance|Summary|overrides_not_loaded  1 when the status is absent, parse failed, fetch
                                                failed with no copy in force, or fetch failed 3
                                                or more cycles in a row (raises "Compliance
                                                overrides file not loaded"), else 0
```

`absent` means the configuration-file store has no file by that name:
no overrides apply, and any copy read earlier is dropped. `parse failed`
and `fetch failed` keep the last copy read, when there is one. One or two
fetch failures in a row with a copy in force do not raise the alert; a
fetch failure with no copy in force does at once.

**The rollup counts only objects with a VCF Ops resource (build 88).**
An object counts in `scored`, `non_compliant`, `no_benchmark`,
`score_sum`, `All` and the `Benchmark` buckets only when the adapter found
its VMWARE resource, that is, only when it could push the result
somewhere. An object vCenter lists with no match is not read or scored
at all; it is counted in `Rollup|<K>|unmatched` (pushed with the kind's
other keys, 0 when none), and the adapter log names the unmatched objects
of each kind once per cycle at INFO (name and MOID, the first 20, then
"(+N more)"), in a line that starts `<Kind>: N object(s) with no matching
VCF Ops resource`. Typical causes: an object created since the VMWARE
adapter's last collection, or one the VMWARE adapter does not collect.
For the vCenter kind the count is always 0 when pushed: the rollup lives
on the vCenter object, so an unmatched vCenter pushes no rollup at all.
If VCF Ops' resource list for a kind cannot be read in a cycle, the kind
is not scored and is held back like a failed vCenter listing
(`Rollup|incomplete` = 1) rather than reported as all unmatched.

**vSphere Pods are out of scope (build 88).** A VM whose guest id starts
with `crx` (`crxPod1Guest`, guest "VMware CRX Pod 1 (64-bit)", and any
other `crx...` id, in any case) is a vSphere Pod: VCF Ops models it as
kind Pod, not VirtualMachine, and the SCG VM controls do not apply. It is
skipped before scoring and counted only in `Rollup|VM|skipped_pods`,
never as unmatched. The guest id comes from the bulk VM listing, so this
costs no extra call. Each skipped Pod is named in the adapter log at
DEBUG; the per-cycle count is at INFO ("vSphere Pod VM(s) skipped"). If
the bulk listing cannot return the guest id in a cycle, Pods are not
recognised that cycle and show up under `Rollup|VM|unmatched` instead.

**Unreadable data is skipped and flagged per object (build 95, Scott
2026-10-14: "if we have missing data we just don't log it - but flag the
stale metric, and then that becomes an alarm").** A setting the adapter
could not read this cycle is not pushed: its last `Compliant` value and
any per-control alert stay as they were. It is never a pass and never a
failure: it is outside the object's `score` (passed over evaluated, over
what was read), outside `non_compliant` and outside every rollup count
and pass rate. The object is flagged instead: `has_unreadable` = 1 with
`unreadable_count`, `unreadable_reason` and `unreadable_controls`, listed
on the Objects with Unreadable Controls view beside the Controls Passing
tile, and after two cycles in a row its "Compliance data not collected"
alert fires (see Alerts). An object with nothing readable pushes only
those signals, so its last score stays on screen, marked by Not Fully
Read beside it in the per-kind views and the host details. A partial
read outage still moves the score, over what was read, and can raise or
cancel Host Compliance Score Degraded; only a whole-object outage leaves
the score untouched. This replaces the build 63 rule (owner decision 2026-09-23), under
which an unreadable setting counted as failing, pushed -1, made the object
non-compliant and an all-unreadable object scored 0. `score` and
`avg_score` are not pushed when nothing was read (an all-unreadable
object, a no-benchmark object, a non-vSAN cluster); VCF Ops then keeps
showing the last value it had, so read them with `has_unreadable` and
`no_benchmark` (per object, both pushed every cycle; `total_count` is not
pushed when nothing was read, so it is stale too) and `scored` (per
vCenter, pushed every cycle).

**The percentage is controls passing (build 95, Scott 2026-10-14).**
Every percentage the dashboards show for a kind, a vCenter or the
environment is `pass_rate`: controls passed over controls evaluated,
counting each control on each object once. Before build 95 they showed
`avg_score`, the mean of the object scores, which weighs every object the
same: a port group with 7 evaluated controls (SCG 9.1) counted as much as
a host with 56, so many well-configured port groups and VMs could lift the
environment above every low-count kind (prod, 2026-10-14: 79.9% while
vCenters scored 50 and vDS 75). Two kinds of number now sit side by side:
- **Pass rate**, over controls: how much of the guide is met.
- **Object counts** (`scored`, `non_compliant`, `no_benchmark`): how many
  objects had at least one control read and how many have at least one
  failing control that was read.

Both come from what was read this cycle. Unreadable controls are in
neither part of the pass rate (not passes, not in the denominator) and
there is no unreadable rollup key: missing data shows per object, on the
Objects with Unreadable Controls list and in the "Compliance data not
collected" alerts. The per-object `score` follows the same rule (build
95), so an object's score and its kind's pass rate agree. An object with
nothing read is counted only in its `Benchmark|<B>|objects` bucket (a
version-unreadable object in `unknown`). When nothing of a kind could be
read, its `pass_rate` is not pushed and the cell keeps its last value
(never 100 for nothing); the list and the alert say why. Manual-review and
override-skipped controls are never evaluated and are in no count.
`avg_score` and `score_sum` are still pushed; the alerts on a host's own
`score` are unchanged.

## Keys on the pack's Compliance World

The Compliance World is one object shared by every adapter instance. The
adapter pushes the last scan time and (build 90) the overrides status
onto it, so those show the last instance to collect; read each vCenter
object for a specific instance. The environment totals are computed by
VCF Operations, not pushed (build 82):
```
Summary|last_scan_timestamp          property, pushed: last scan by any instance
Summary|overrides_file               property, pushed (build 90): last instance to collect
Summary|overrides_status             property, pushed (build 90): last instance to collect
Summary|overrides_skipped            pushed (build 90): last instance to collect
Summary|overrides_overridden         pushed (build 90): last instance to collect
Summary|overrides_not_loaded         pushed (build 90): last instance to collect
Rollup|Environment|scored            sum of every vCenter's VCF-CF Compliance|Rollup|All|scored
Rollup|Environment|non_compliant     sum of every vCenter's VCF-CF Compliance|Rollup|All|non_compliant
Rollup|Environment|no_benchmark      sum of every vCenter's VCF-CF Compliance|Rollup|All|no_benchmark
Rollup|Environment|avg_score         % : summed Rollup|All|score_sum / summed Rollup|All|scored
                                     (kept, no longer displayed, build 95)
Rollup|Environment|controls_evaluated  build 95: sum of every vCenter's Rollup|All|controls_evaluated
Rollup|Environment|controls_passed     build 95: sum of every vCenter's Rollup|All|controls_passed
Rollup|Environment|pass_rate           build 95, % : summed Rollup|All|controls_passed /
                                       summed Rollup|All|controls_evaluated * 100
```

- **Engine-computed.** The `Rollup|Environment` keys are
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
- **`pass_rate` is a ratio of sums** (build 95): summed `controls_passed`
  over summed `controls_evaluated` across the vCenters, never a mean of
  per-vCenter rates. With nothing evaluated anywhere it is expected to have
  no data (0 over 0), never 100; read it with `controls_evaluated`.
- **The parent/child link.** Each adapter instance, every cycle, makes its
  own vCenter's `VMwareAdapter Instance` a child of the Compliance World
  through an additive Suite API relationship add (it never replaces the
  links other instances made). The link is never removed: a vCenter whose
  compliance adapter instance is deleted stays a child of the Compliance
  World, and whether its last rollup values keep counting in the totals
  has not been observed yet.

## Dashboards

The pak installs four dashboards (plus their nine views) and the
Compliance World Summary tab:

| Dashboard | What it is for |
|---|---|
| [VCF Content Factory] Compliance Environment Overview | The landing page: environment controls passing, beside it the objects with unreadable controls (build 95), non-compliant objects and objects without a benchmark, compliance by vCenter and object type, objects per SCG version, the score trend, and open compliance alerts. |
| [VCF Content Factory] Compliance ESX Hosts | Pick a scope (vSphere World or one vCenter), see its hosts worst first with score and applied SCG, select a host to see its failing controls and their runbooks (that panel is currently empty, issue #30). |
| [VCF Content Factory] Compliance VMs | The same flow for VMs, built for thousands of objects (sorted list and totals, no heatmap). |
| [VCF Content Factory] Compliance vCenter & Networking | One page for the low-count kinds: vCenter, cluster, distributed switch and distributed portgroup lists, worst first, with the selected object's failing controls. |
| [VCF Content Factory] Compliance World Summary | Not in the dashboard menu: it is the **Summary tab** of the pack's Compliance World object (build 88; find Compliance World in the inventory and open it). The Environment Overview re-cut for that tab: the four environment tiles, the objects with unreadable controls, the last scan time, compliance by vCenter and object type, the score trend, objects per SCG version, and the open compliance alerts of the vCenter selected in the table. |

The Environment Overview's four tiles (Controls Passing, Non-Compliant,
Without Benchmark, Objects Scored) and its trend (Controls Passing and
Non-Compliant Objects) read the
Compliance World's `Rollup|Environment|*` keys (above). The per-vCenter
table shows the vCenter's All Controls Passing (%), Passed and Evaluated
(`Rollup|All|pass_rate`, `controls_passed`, `controls_evaluated`; summed
Passed over summed Evaluated in the totals row is the Controls Passing
tile), Controls Passing (%) per kind (`Rollup|<K>|pass_rate`; the vCenter
kind's column is "vCenter Appliance Controls Passing", the appliance
controls only, not the vCenter's overall rate), and per kind a "Not in VCF Ops"
column (`Rollup|<K>|unmatched`, issue #39); its totals row sums the count
columns, not the percentages. Objects by SCG Version lists the newest
guide first and spans the page (issue #32). The ESX Hosts heatmap colours
on a fixed 0 to 100 scale: red below 80, amber 80 to 95, green from 95
(issue #33). No widget needs
policy enablement. The Objects Scored tile sits beside Non-Compliant
Objects so that a 0 non-compliant reading is always shown with its
denominator: 0 non-compliant with 0 scored means nothing was evaluated,
not all clear.

**Objects with Unreadable Controls** (build 95), next to the Controls
Passing tile on the Environment Overview and the World Summary: the view
"[VCF Content Factory] Compliance Objects with Unreadable Controls" lists
every ESX host, VM, vCenter, cluster, distributed switch and distributed
portgroup whose `has_unreadable` is 1, with its kind (`object_kind`),
`unreadable_count`, `unreadable_reason` and `unreadable_controls`. For
an object whose product version could not be read, `unreadable_count`
is not pushed, so the count shown is from an earlier cycle; its
`unreadable_controls` reads `(not known: ...)` and is current. It is the signal for missing
data: the percentages count only what was read, so an object or a whole
kind that could not be read keeps its last value on the tiles and in the
table, and appears here. An empty list means every object the adapter
visited on its last cycle was fully read. It says nothing about objects
the cycle did not visit: when a kind's listing failed (that kind is held
back) or vCenter could not be reached at all, those objects keep the
flag from their last visit, so they stay off (or on) the list as they
were. Both cases set `Rollup|incomplete` = 1 on the vCenter, which
raises "Compliance data not collected (vCenter)"; an unreachable vCenter
also leaves the ComplianceWorld resource in collection status down (no
connection) or error (login or certificate), and the adapter log names
the failed listing or the connection error.

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
  portgroup), severity Immediate, raised when `has_unreadable` = 1 for
  two cycles in a row (build 95: some or all of the object's settings
  could not be read, an object whose version could not be read included)
  and cleared after one cycle that reads everything. The build 65
  `unreadable_count` > 0 OR `collection_failed` = 1 pair is retired. On
  the vCenter the alert also fires on `Rollup|incomplete` = 1 (an
  inventory listing failed). Its recommendation explains what is not
  current (the setting is not pushed; the score counts only what was
  read), the causes (connectivity, permissions, read method not supported
  on this version), where to see which settings and why
  (`unreadable_reason`, `unreadable_controls`, `unreadable_count`, the
  Objects with Unreadable Controls list), and what to check. Alert ids
  `vcfcf_compliance_collection_{host,vm,vcenter,cluster,vds,portgroup}`;
  symptom ids `vcfcf_compliance_collection_<kind>_unreadable` (kept from
  build 63, new condition).

- `VCF Content Factory Compliance Alert: Compliance overrides file not
  loaded` (build 90) on the vCenter object (`VMwareAdapter Instance`),
  severity Warning, raised when `VCF-CF Compliance|Summary|overrides_not_loaded`
  is 1: the instance's Overrides file names a file the configuration-file
  store does not have, or one that is not valid XML. Its recommendation
  says how to tell which and what to fix. Alert id
  `vcfcf_compliance_overrides_vcenter`; raises and cancels after 1 cycle.

All compliance alerts are type Compliance (subType 21).

Wait and cancel cycles (build 86): the per-control alerts and the score
alert, and their symptoms, raise after 1 cycle and cancel after 3
consecutive cycles without the condition. A fixed control therefore
clears its alert after 3 cycles (15 minutes at the 5 minute default).
Since build 95 a cycle in which a failing control could not be read
pushes nothing for it, so the finding stays open. The collection alerts'
`has_unreadable` symptom raises after 2 consecutive cycles and cancels
after 1 (build 95); the vCenter's `Rollup|incomplete` symptom and the
overrides alert raise and cancel after 1 cycle.

## Limitations

- No remediation actions.
- Controls the adapter cannot read over vim25 / esxcli / VAMI are
  informational; see `profiles/UNAUDITED_CONTROLS.md`.
- Most SCG cluster (vSAN) controls need the vSAN Management SDK, which is
  not on the adapter classpath.
