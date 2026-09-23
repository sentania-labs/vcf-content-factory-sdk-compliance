# VCF Content Factory Compliance — Reference

Generated from `describe.xml` and `resources.properties`.

## Adapter

| Field | Value |
|---|---|
| Adapter Kind | `vcfcf_compliance` |
| Tier | 2 (Java SDK) |
| Monitoring Interval | 60 minutes |
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
| Custom Profile CSV Path (required if profile is Custom) | `custom_profile_path` | — | No |
| Allow Insecure SSL (true to disable cert validation; default false = validate against platform trust store) | `allowInsecure` | false | No |

---

## Object Types

### Compliance World

**Identifier**: `world_id` (World ID)

#### Summary

| Key | Label | Type | Unit | Monitored |
|---|---|---|---|---|
| `last_scan_timestamp` | Last Scan Timestamp | property | — | — |

---

The keys the adapter pushes onto VMWARE resources (per control, per
object, and the per-vCenter rollup) are not declared in describe.xml;
they are listed in the repo README under "Keys pushed onto VMWARE
resources".
