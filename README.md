# VCF Content Factory Compliance Adapter

Monitors vSphere for VMware Security Configuration Guide (SCG) compliance
by querying vCenter configuration and evaluating each object against the
SCG that matches its version. Covers ESX hosts, VMs, vCenter, clusters
(vSAN controls), distributed switches and distributed portgroups. Pushes
per-control results, per-object scores and flags onto the existing VMWARE
resources via ARIA_OPS stitching, a per-vCenter rollup onto each vCenter
object, and raises one compliance alert per failing control with the SCG
remediation as its recommendation.

## Documentation

Full docset (overview, installing & configuring, inventory tree): [`docs/README.md`](docs/README.md).

## Quick start

1. Build: `python3 -m vcfcf_managementpacks build-sdk content/sdk-adapters/compliance`
2. Install the `.pak` from `dist/` via VCF Ops UI or CLI
3. Add adapter instance: provide vCenter host and credentials; leave the
   benchmark profile at `Auto (by version)` unless you want one SCG forced
4. Wait one collection cycle (default 60 minutes)
5. Check an object: Environment > select host / VM / vCenter > All Metrics
   > VCF-CF Compliance

## Adapter instance configuration

| Field | Required | Default | Description |
|---|---|---|---|
| vCenter Host | Yes | - | vCenter FQDN or IP |
| Username | Yes | - | vCenter SSO credentials |
| Password | Yes | - | vCenter SSO credentials |
| Benchmark Profile | Yes | Auto (by version) | Auto (by version), VMware_SCG_6.7, VMware_SCG_7.0, VMware_SCG_8.0, VMware_SCG_9.0, VMware_SCG_9.1, or Custom |
| Custom Profile Path | No | - | Filesystem path to CSV if Custom |
| Allow Insecure SSL | No | false | Accept self-signed certificates |
| Read vCenter appliance settings | No | false | Read the vCenter appliance (VAMI) settings (SSH, NTP, syslog, TLS profile, root password expiry, FIPS). Off: those controls are reported for manual review. On: needs the collection account in the vsphere.local SSO group `SystemConfiguration.Administrators`, which also grants appliance write access (no read-only appliance role exists) |

**Existing instances keep their stored profile on upgrade.** VCF Ops
stores the configured value on each adapter instance, and a pak upgrade
does not rewrite it (the new default applies to new instances only). The
devel instances, for example, are stored as fixed `VMware_SCG_9.1` and keep
scoring every object against SCG 9.1 until someone edits them to
`Auto (by version)`. An instance with no stored value keeps the pre-v3
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

The adapter's own Compliance World carries only
`Summary|last_scan_timestamp`: it is one object shared by every adapter
instance, so per-vCenter numbers on it would be last-writer-wins.

## Dashboards and super metrics

The pak installs four dashboards (plus their eight views):

| Dashboard | What it is for |
|---|---|
| [VCF Content Factory] Compliance Environment Overview | The landing page: environment score, non-compliant objects and objects without a benchmark, compliance by vCenter and object type, objects per SCG version, the score trend, and open compliance alerts. |
| [VCF Content Factory] Compliance ESX Hosts | Pick a scope (vSphere World or one vCenter), see its hosts worst first with score and applied SCG, select a host to see its failing controls and their runbooks. |
| [VCF Content Factory] Compliance VMs | The same flow for VMs, built for thousands of objects (sorted list and totals, no heatmap). |
| [VCF Content Factory] Compliance vCenter & Networking | One page for the low-count kinds: vCenter, cluster, distributed switch and distributed portgroup lists, worst first, with the selected object's failing controls. |

The Environment Overview's score tiles and trend read four bundled super
metrics, all assigned to `VMWARE / vSphere World`: Compliance Objects
Scored, Compliance Non-Compliant Objects, Compliance Objects Without
Benchmark, and Compliance Average Score. **They must be enabled in the
policy active on vSphere World** (in the policy editor, Metrics and
Properties, filter on "Compliance"; the exact menu path differs between
Ops 9.0 and 9.1),
or those tiles and the trend stay empty. Whether the pak import enables
them automatically is **unconfirmed**; it will be checked at the devel
install. The other widgets read adapter data directly and need no
enablement. Compliance Average Score shows no data until the first v3
collection cycle has scored something.

## Alerts

- `Host Compliance Score Degraded` (HostSystem, score below 95 / 80).
- One compliance alert per scored SCG control, named
  `<control_id>: <title>`, raised when that control's `Compliant` is 0,
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

## Limitations

- No remediation actions.
- Controls the adapter cannot read over vim25 / esxcli / VAMI are
  informational; see `profiles/UNAUDITED_CONTROLS.md`.
- Most SCG cluster (vSAN) controls need the vSAN Management SDK, which is
  not on the adapter classpath.

## Building from source

You don't need this repo's CI or the VCF Content Factory checkout to
build the `.pak` — the toolchain is a portable tarball. You need:

- **JDK 11+** (`javac` + `jar` on PATH)
- **python3** with `pyyaml` (`python3 -m pip install pyyaml`)
- **The GitHub CLI** (`gh`) — used to download the build toolchain
  below. The factory repo is public, so no `gh auth login` is needed
  for the download (authenticate only if you hit anonymous API rate
  limits). No `gh`? See the `curl` alternative under step 1.
- **The Broadcom adapter SDK jar** (`vrops-adapters-sdk-2.2.jar`).
  This is a Broadcom build artifact with no public redistribution
  channel — it is **never** bundled in the toolchain or this repo.
  Get it from your own VCF Operations appliance:

  ```
  scp root@<appliance>:/usr/lib/vmware-vcops/common-lib/vrops-adapters-sdk-2.2.jar .
  ```

  (Also present at
  `/usr/lib/vmware-vcops/suite-api/WEB-INF/lib/vrops-adapters-sdk.jar`.
  Partners can pull it from the Broadcom TAP / partner SDK portal
  instead.)

Then, from the root of this repo:

```bash
# 1. Fetch the build toolchain (pin a full sdk-buildkit-vX.Y.Z tag for
#    reproducibility, or use the floating major sdk-buildkit-v1)
gh release download sdk-buildkit-v1 \
  --repo sentania-labs/vcf-content-factory \
  --pattern 'sdk-buildkit-*.tgz'
# No gh? The asset is public — fetch it with curl instead:
#   curl -sL https://github.com/sentania-labs/vcf-content-factory/releases/download/sdk-buildkit-v1/sdk-buildkit-v1.tgz -o sdk-buildkit-v1.tgz
tar xzf sdk-buildkit-*.tgz

# 2. Point the kit at your SDK jar and build
export VCFCF_SDK_JAR=/path/to/vrops-adapters-sdk-2.2.jar
python3 -m sdk_buildkit validate-sdk .   # cheap loop: compile-check
python3 -m sdk_buildkit build-sdk .      # emits the .pak
```

The kit carries everything else it needs (including the
`vcfcf-adapter-base.jar` framework runtime that ends up in the pak's
`lib/`). `validate-sdk` is the fast iteration loop; exhaust it before
building paks.

**Dev builds vs releases.** Anything you build this way is a *dev
build*. The **official** artifact for this repo is the one its own CI
builds and attaches to a GitHub Release when a `v*` tag is pushed —
deterministic, no developer machine in the path.

**If you fork this repo**, the CI workflow
(`.github/workflows/build-pak-on-tag.yml`) needs one adjustment
before your own `v*` tags will build (it already runs on GitHub-hosted
`ubuntu-latest`, so no runner change is needed).

**SDK jar sourcing**: the upstream workflow fetches the Broadcom
   jar from a private repo via an `SDK_RUNTIME_SSH_KEY` deploy-key
   secret you won't have. Replace that step with your own source —
   e.g. store the appliance-extracted jar in your own private repo or
   an Actions secret/artifact store. Then **also update the
   `--sdk-jar` argument** on the `build-sdk` line of the workflow to
   point at wherever your replacement step puts the jar. The explicit
   `--sdk-jar` flag overrides `VCFCF_SDK_JAR`, so setting the env var
   alone is not enough — if you leave `--sdk-jar _sdk_runtime/...` in
   place the build will look for the upstream path and fail. Do **not**
   commit the jar to a public repo (no redistribution).
