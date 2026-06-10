# Overview — VCF Content Factory Compliance

## What's in the Pack

VCF Content Factory Compliance is a Tier 2 (Java SDK) management pack that
evaluates ESXi host and vCenter configuration against a security
configuration benchmark and reports per-control results and aggregate
compliance scores into VCF Operations.

The adapter connects to a vCenter, walks the inventory over vSphere SOAP
(vim25), reads each host's effective configuration (vim properties,
advanced settings, esxcli service/firewall/account state, and the vCenter
appliance VAMI policy endpoints), and scores it against the active
profile. Results are pushed onto the existing VMWARE resources so an
operator sees compliance posture in-place on the hosts and vCenter they
already monitor — no separate object tree to navigate for per-control
detail.

Bundled profiles cover the VMware Security Configuration Guide (SCG) for
ESXi 8.x and 9.x and the CIS vSphere Foundations Benchmark. A custom
profile can be supplied as an SCG-format CSV.

### Resource kinds

The adapter owns a single synthetic resource kind:

| Kind | Key | Purpose |
|------|-----|---------|
| Compliance World | `ComplianceWorld` | Fleet rollup anchor — one singleton per adapter instance. |

The Compliance World carries the fleet-level rollup metrics; all per-host
and per-control detail lives on the foreign VMWARE resources it stitches
to (see Cross-Adapter Behavior).

### Metrics scope

The Compliance World publishes a small fixed set of fleet rollup signals
(see `REFERENCE.md` for the authoritative list):

- `total_hosts` — hosts scanned this cycle
- `avg_host_score` — fleet average host compliance score (%)
- `hosts_below_threshold` — hosts under the alert threshold
- `hosts_scored_stale` — hosts whose contribution to the average came from
  a last-known cached score rather than a live read this cycle
- `profile_name`, `last_scan_timestamp` — properties

Per-host detail is pushed onto each VMWARE HostSystem as properties and
stats (the per-control `Actual`/`Expected`/`Compliant`/`Description`
quartet plus the host aggregate `score`/`pass_count`/`fail_count`/
`total_count`/`profile_name`). The exact control set and count depend on
the active profile.

## Cross-Adapter Behavior

This pack is an **ARIA_OPS-style metric pusher**, not a standalone object
tree. It resolves the real VMWARE resources that the platform's vCenter
adapter already discovered and pushes compliance properties and stats onto
them via the Suite API:

- **VMWARE HostSystem** — per-control results and the per-host aggregate
  score. vim25-backed hosts resolve by their stable MOID identity.
- **VMWARE vCenter (VMwareAdapter Instance)** — vCenter-appliance controls
  resolve the vCenter object by `VCURL` (vCenter FQDN) and `VMEntityVCID`
  (vCenter Instance UUID), since that object is not vim25-backed and has no
  MOID.

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
  the handful of controls that happened to read. A `totalCount == 0` host
  pushes no `score` sentinel at all (absent, not a green 100), so per-host
  compliance symptoms see "no data" instead of a false pass.

- **`hosts_scored_stale` is first-class.** When a host is unreadable this
  cycle but has a last-known score, that score is folded into the fleet
  `avg_host_score` so an unreadable host does not silently shrink the
  denominator — and the count of such hosts is published every cycle as
  `hosts_scored_stale`. An operator can see directly how much of the fleet
  average is live versus carried-forward. Hosts never read since process
  start stay excluded entirely (the adapter never invents an unobserved
  score). The last-known cache is in-memory and resets on collector
  restart, so the first cycle(s) after a restart average readable-only
  until it re-warms.

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

- **Hosts and vCenter only.** VM-level controls are limited; the focus is
  ESXi host and vCenter appliance posture.
- **No remediation.** The pack reports compliance; it does not remediate
  (remediation is a planned future phase).
- Some controls requiring data channels the adapter cannot reach on a given
  target are classified as unaudited rather than scored — see
  `profiles/UNAUDITED_CONTROLS.md` in the pack source.
