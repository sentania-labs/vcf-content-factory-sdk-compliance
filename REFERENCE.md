# VCF Content Factory Compliance — Reference

Generated from `describe.xml` and `resources.properties`.

## Adapter

| Field | Value |
|---|---|
| Adapter Kind | `vcfcf_compliance` |
| Tier | 2 (Java SDK) |
| Monitoring Interval | 5 minutes |
| License Required | No |

### Credentials

| Field | Key | Type |
|---|---|---|
| Username | `username` | string |
| Password | `password` | string (masked) |

### Connection Settings

| Field | Key | Default | Required |
|---|---|---|---|
| vCenter Host / IP | `vcenter_host` | — | Yes |
| Compliance Profile | `benchmark_profile` | Auto (by version) | Yes |
| Overrides file (name of your copy in Administration > Configuration Files, no extension) | `overrides_file` | - | No |
| Allow Insecure SSL (true to disable cert validation; default false = validate against platform trust store) | `allowInsecure` | false | No |
| Read vCenter appliance settings (true needs the account in SSO group SystemConfiguration.Administrators, which also grants appliance write access) | `read_appliance_settings` | false | No |

The Overrides file setting (build 90) names your copy of
`compliance_overrides_template`; see [docs/overrides.md](docs/overrides.md).

---

## Object Types

### Compliance World

**Identifier**: `world_id` (World ID)

#### Summary

| Key | Label | Type | Unit | Monitored |
|---|---|---|---|---|
| `last_scan_timestamp` | Last Scan Timestamp | property | — | — |
| `overrides_file` | Overrides File | property | - | - |
| `overrides_status` | Overrides Status | property | - | - |
| `overrides_skipped` | Overrides Skipped | metric | - | yes |
| `overrides_overridden` | Overrides Overridden | metric | - | yes |
| `overrides_not_loaded` | Overrides Not Loaded | metric | - | yes |

The `overrides_*` keys (build 90) show the overrides file of the last
adapter instance to collect, because every instance shares the Compliance
World. Each vCenter object carries its own instance's copy under
`VCF-CF Compliance|Summary|`.

#### Rollup > Environment

Engine-computed (`<ComputedMetrics>` on the ComplianceWorld kind, build
82): summed across the Compliance World's `VMWARE / VMwareAdapter
Instance` children from each vCenter's `VCF-CF Compliance|Rollup|All|*`
keys. No adapter instance pushes them and no policy enablement is needed.
One collection interval behind the per-vCenter rollup. See
[docs/data-reference.md](docs/data-reference.md), "Keys on the pack's
Compliance World".

| Key | Label | Type | Unit | Monitored |
|---|---|---|---|---|
| `Rollup\|Environment\|scored` | Objects Scored | metric | none | yes |
| `Rollup\|Environment\|non_compliant` | Non-Compliant Objects | metric | none | yes |
| `Rollup\|Environment\|no_benchmark` | Objects Without Benchmark | metric | none | yes |
| `Rollup\|Environment\|avg_score` | Average Score | metric | % | yes |

---

The keys the adapter pushes onto VMWARE resources (per control, per
object, and the per-vCenter rollup) are not declared in describe.xml;
they are listed in [docs/data-reference.md](docs/data-reference.md)
under "Keys pushed onto VMWARE resources".
