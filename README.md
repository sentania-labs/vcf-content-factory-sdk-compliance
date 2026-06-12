# VCF Content Factory Compliance Adapter

Monitors ESXi hosts for CIS benchmark compliance by querying vCenter
configuration and evaluating controls against a user-selectable security
profile. Pushes per-control compliance properties and aggregate scores
onto existing VMWARE HostSystem resources via ARIA_OPS stitching.

## Documentation

Full docset (overview, installing & configuring, inventory tree): [`docs/README.md`](docs/README.md).

## Quick start

1. Build: `python3 -m vcfops_managementpacks build-sdk content/sdk-adapters/compliance`
2. Install the `.pak` from `dist/` via VCF Ops UI or CLI
3. Add adapter instance: provide vCenter host, credentials, select benchmark profile
4. Wait one collection cycle (default 60 minutes)
5. Check host compliance: Environment > select host > All Metrics > VCF-CF Compliance

## Adapter instance configuration

| Field | Required | Default | Description |
|---|---|---|---|
| vCenter Host | Yes | - | vCenter FQDN or IP |
| Username | Yes | - | vCenter SSO credentials |
| Password | Yes | - | vCenter SSO credentials |
| Benchmark Profile | No | CIS_8.0 | CIS_8.0, CIS_9.0, or Custom |
| Custom Profile Path | No | - | Filesystem path to CSV if Custom |
| Allow Insecure SSL | No | true | Accept self-signed certificates |

## Benchmark profiles

Bundled profiles ship with the pak under `profiles/`:
- `cis_esxi_8.0.csv` — CIS vSphere 8.0 Security Configuration Guide

Custom profiles must follow the VMware SCG CSV format (27 columns).
Upload the CSV to the VCF Ops appliance and reference the path.

## Property naming

Per-control properties on VMWARE HostSystem:
```
VCF-CF Compliance|<profile>|<scg-id>|Actual
VCF-CF Compliance|<profile>|<scg-id>|Expected
VCF-CF Compliance|<profile>|<scg-id>|Compliant   (0 or 1)
VCF-CF Compliance|<profile>|<scg-id>|Description
```

Aggregate metrics:
```
VCF-CF Compliance|score          (0-100%)
VCF-CF Compliance|pass_count
VCF-CF Compliance|fail_count
VCF-CF Compliance|total_count
VCF-CF Compliance|profile_name
```

## Phase 1 limitations

- REST-only vCenter API access — controls requiring SOAP (advanced
  host settings) are skipped as N/A until Phase 1.1
- Hosts only (VMs are a stretch goal)
- No remediation actions (Phase 2)

## Building from source

You don't need this repo's CI or the VCF Content Factory checkout to
build the `.pak` — the toolchain is a portable tarball. You need:

- **JDK 11+** (`javac` + `jar` on PATH)
- **python3** with `pyyaml` (`python3 -m pip install pyyaml`)
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
(`.github/workflows/build-pak-on-tag.yml`) needs two adjustments
before your own `v*` tags will build:

1. **Runner**: it targets a `self-hosted` runner pool — switch
   `runs-on` to `ubuntu-latest` (the workflow comments call this out).
2. **SDK jar sourcing**: the upstream workflow fetches the Broadcom
   jar from a private repo via an `SDK_RUNTIME_SSH_KEY` deploy-key
   secret you won't have. Replace that step with your own source —
   e.g. store the appliance-extracted jar in your own private repo or
   an Actions secret/artifact store — and point `VCFCF_SDK_JAR` at it.
   Do **not** commit the jar to a public repo (no redistribution).
