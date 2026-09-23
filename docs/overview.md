# Overview — VCF Content Factory Compliance

## Stitched onto VMWARE resources (start here)

Almost everything this pack produces lives on objects the VMWARE (vSphere)
adapter already owns, not on the pack's own object. The generated
inventory tree shows only the pack's own `ComplianceWorld`, so use this
list to find the data:

| VMWARE object | What the pack pushes onto it |
|---|---|
| HostSystem, VirtualMachine, VMwareAdapter Instance (vCenter), ClusterComputeResource, VmwareDistributedVirtualSwitch, DistributedVirtualPortgroup | Per control: `VCF-CF Compliance\|<control_id>\|{Actual, Expected, Description}` (properties) and `...\|Compliant` (1 / 0 / -1 not evaluated). Per object: `profile_name`, `score`, `pass_count`, `fail_count`, `total_count`, `unreadable_count`, `non_compliant`, `no_benchmark`. |
| VMwareAdapter Instance (vCenter) | Per-vCenter rollup: `VCF-CF Compliance\|Rollup\|<All, Host, VM, vCenter, Cluster, vDS, Portgroup>\|{scored, non_compliant, no_benchmark, score_sum, avg_score}`, `Rollup\|Host\|scored_stale`, and `Rollup\|Benchmark\|<SCG_6.7 ... SCG_9.1, none, unknown>\|objects`. |
| The same six kinds | 144 compliance alerts (type Compliance, subType 21), one per scored SCG control, named `<control_id>: <title>`, raised when that control's `Compliant` is 0, each with the SCG remediation as its recommendation. Plus the Host Compliance Score Degraded alert on HostSystem. |

The full key list, with when each key is pushed, is in the repo
`README.md` under "Keys pushed onto VMWARE resources".

## What's in the Pack

VCF Content Factory Compliance is a Tier 2 (Java SDK) management pack that
evaluates ESXi host, VM, vCenter, cluster (vSAN), distributed switch and
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
version (hosts by ESXi version, VMs by their host's ESXi version,
everything else by the vCenter version); an object whose version has no
bundled SCG is reported as "no benchmark" and not scored. A fixed SCG or
a custom canonical-schema CSV can be forced instead.

### Resource kinds

The adapter owns a single synthetic resource kind:

| Kind | Key | Purpose |
|------|-----|---------|
| Compliance World | `ComplianceWorld` | Adapter liveness anchor, one object shared by every adapter instance. |

The Compliance World carries only `Summary|last_scan_timestamp` (the last
scan by any instance). Because every adapter instance writes the same
world object, fleet numbers on it would be last-writer-wins across
vCenters, so since build 57 they live on each vCenter object instead (see
below). All per-object and per-control detail lives on the foreign VMWARE
resources the adapter stitches to.

### Metrics scope

On every evaluated VMWARE object: the per-control
`Actual`/`Expected`/`Description` properties and `Compliant` metric
(1 / 0 / -1 not evaluated), plus `score`, `pass_count`, `fail_count`,
`total_count`, `unreadable_count`, `non_compliant`, `no_benchmark` and the
`profile_name` property. On each vCenter (`VMwareAdapter Instance`): the
per-vCenter rollup `VCF-CF Compliance|Rollup|<kind>|{scored,
non_compliant, no_benchmark, score_sum, avg_score}` for All, Host, VM,
vCenter, Cluster, vDS and Portgroup, plus objects per benchmark. The full
key list is in the repo README.

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
  vim25-backed and has no MOID.

Transport is the **ambient Suite API** — the adapter pushes onto the local
VCF Operations instance using the collector's ambient credentials; no Suite
API host/credential fields are configured. If the Suite API is unavailable
on a collector, the affected stitch is skipped for that cycle and
collection continues; compliance is never failed over a stitch error.

## Notable Behaviors

- **Unreadable is never flattered.** A host or control the adapter could
  not read is never folded into a passing score. A channel that vanishes
  (e.g. a disconnected host whose OptionManager is null) marks the whole
  host's controls UNREADABLE — counted, excluded from the score numerator
  and denominator — rather than producing a flattering partial score from
  the handful of controls that happened to read. A `totalCount == 0` object
  pushes no `score` (never a stand-in 100 or 0), but VCF Ops keeps showing
  the last score it had, and the score symptoms keep evaluating that last
  value. So read `score` together with `total_count` (0 when nothing was
  scored) and `no_benchmark`. The counters are pushed every cycle, zeroed
  when nothing was scored, with one exception: when the version that
  governs the object's SCG cannot be read (and there is no previous SCG to
  fall back on), `unreadable_count` is NOT pushed, because the adapter does
  not know which SCG's controls apply; its last value stays.
  `non_compliant` = 1 in that case.

- **Per-vCenter averages when nothing was scored.** `Rollup|<K>|avg_score`
  is pushed only when `Rollup|<K>|scored` > 0; `scored` itself is pushed
  every cycle, 0 when nothing of that kind was scored. An `avg_score` next
  to `scored` = 0 is therefore a retained value from an earlier cycle, and
  the Overview view shows `non_compliant` / `scored` beside each average so
  that is visible at a glance.

- **Version unreadable is not "no benchmark".** If the adapter cannot read
  the version that governs an object's SCG, it scores the object against
  the SCG it had last cycle. With no previous SCG, the object is reported
  as unreadable: non-compliant, not scored, counted in the rollup's
  `unknown` benchmark bucket. Only a version the adapter read, with no
  bundled SCG, is "no benchmark".

- **Unreadable counts as non-compliant, never as failing a control.**
  An object with any unreadable control has `non_compliant` = 1, but the
  unreadable control itself reports `Compliant` = -1, so its per-control
  alert (which fires on 0) does not hand out a remediation runbook for a
  setting the adapter could not read.

- **Stale host scores are visible.** When a host is unreadable this cycle
  but has a last-known score, that score is folded into its vCenter's
  `Rollup|Host` average so an unreadable host does not silently shrink the
  denominator, and the count of such hosts is published every cycle as
  `Rollup|Host|scored_stale`. Hosts never read since process start stay
  excluded (the adapter never invents an unobserved score). The cache is
  in-memory and resets on collector restart.

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
  nothing more to push. If that read fails, the object is skipped for the
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
- **No remediation.** The pack reports compliance; it does not remediate
  (remediation is a planned future phase).
- Some controls requiring data channels the adapter cannot reach on a given
  target are classified as unaudited rather than scored — see
  `profiles/UNAUDITED_CONTROLS.md` in the pack source.
